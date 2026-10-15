package server

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	SiteConfigFilename = "config.json"
	SitePWFilename     = "pwfile.jsonl"
)

// ServerConfig holds server-level configuration parameters (listeners, TLS, base sites directory).
type ServerConfig struct {
	Addr         string                // HTTPS TCP address to listen on, e.g. ":8443"
	HTTPSAddr    string                // HTTPS TCP address to listen on (alias for Addr)
	HTTPAddr     string                // Optional HTTP TCP address for testing, e.g. "localhost:8080"
	Dir          string                // Base directory containing <site>/ subdirectories
	Sites        map[string]SiteConfig // Optional preconfigured sites keyed by site handle
	CertFile     string                // Path to TLS certificate (optional)
	KeyFile      string                // Path to TLS private key (optional)
	Hosts        []string              // Hostnames/IPs to include in generated certificate
	ReadTimeout  time.Duration         // Maximum duration for reading the entire request
	WriteTimeout time.Duration         // Maximum duration before timing out writes of the response
	IdleTimeout  time.Duration         // Maximum amount of time to wait for the next request when keep-alives are enabled
}

// SiteConfig holds per-site configuration loaded from <dir>/<site>/config.json.
type SiteConfig struct {
	Password      string `json:"pw,omitempty"`             // Shared password for Basic authentication
	Salt          string `json:"salt,omitempty"`           // Salt for deriving crypto username and password hashes
	SiteTitle     string `json:"site_title,omitempty"`     // Custom site title to replace "Stardate" (may be unicode)
	HideStardates bool   `json:"hide_stardates,omitempty"` // If true, hide calculated stardates in the UI
}

// PWFileEntry represents a user record in a site's pwfile.jsonl file.
// The "superuser" and "disabled" attributes only appear when true (via omitempty).
type PWFileEntry struct {
	Handle    string `json:"handle"`
	Display   string `json:"display,omitempty"`
	PW        string `json:"pw,omitempty"`
	PWHash    string `json:"pwhash,omitempty"`
	Superuser bool   `json:"superuser,omitempty"`
	Disabled  bool   `json:"disabled,omitempty"`
}

// DefaultServerConfig returns default server configuration values.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Addr:         ":8443",
		HTTPSAddr:    ":8443",
		Dir:          ".",
		Hosts:        []string{"localhost", "127.0.0.1", "::1"},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// StardateResponse represents the JSON payload returned for stardate queries.
type StardateResponse struct {
	Site        string    `json:"site,omitempty"`
	User        string    `json:"user,omitempty"`
	IsCrypto    bool      `json:"is_crypto,omitempty"`
	IsSuperuser bool      `json:"is_superuser,omitempty"`
	Stardate    float64   `json:"stardate"`
	Formatted   string    `json:"formatted"`
	UTC         string    `json:"utc"`
	Timestamp   int64     `json:"timestamp"`
	Messages    []Message `json:"messages,omitempty"`
}

// AuthUser represents an authenticated user session.
type AuthUser struct {
	Username       string // Original or normalized handle supplied in credentials
	CryptoUsername string // First 10 hex digits of sha256(salt + username + password) if crypto user
	EffectiveUser  string // CryptoUsername if IsCrypto, else Display (or Username)
	CryptoKey      []byte // 32-byte sha256 key if IsCrypto, else nil
	IsCrypto       bool   // True if password has "/" + >= 12 ASCII characters beyond base password
	IsSuperuser    bool   // True if user has "superuser":true in pwfile.jsonl
}

// Site represents a single hosted microblog site.
type Site struct {
	handle     string
	dir        string
	cfg        SiteConfig
	pwFilePath string
	pwMu       sync.RWMutex
	pwUsers    map[string]PWFileEntry
	store      *Store
}

// Store returns the site's message store.
func (site *Site) Store() *Store {
	return site.store
}

// Config returns the site's SiteConfig.
func (site *Site) Config() SiteConfig {
	return site.cfg
}

// Handle returns the normalized site handle.
func (site *Site) Handle() string {
	return site.handle
}

// Server is the multi-site stardate HTTPS (and optional HTTP) server.
type Server struct {
	cfg             ServerConfig
	sitesMu         sync.RWMutex
	sites           map[string]*Site
	tmpl            *template.Template
	httpServer      *http.Server // HTTPS server
	httpPlainServer *http.Server // Optional HTTP server for testing
	listener        net.Listener // HTTPS listener
	httpListener    net.Listener // HTTP listener
}

// NormalizeSiteHandle normalizes a hostname or site handle by stripping any port,
// converting to lowercase, and trimming a leading "www." prefix.
func NormalizeSiteHandle(hostOrHandle string) string {
	s := strings.TrimSpace(hostOrHandle)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	} else if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "www.")
	return s
}

// isValidSiteHandle checks that a normalized site handle is non-empty and safe to use as a subdirectory name.
func isValidSiteHandle(h string) bool {
	if h == "" || h == "." || h == ".." {
		return false
	}
	if strings.HasPrefix(h, ".") {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c == '/' || c == '\\' || c <= 32 || c >= 127 {
			return false
		}
	}
	return true
}

// isValidHandle checks that a user handle is non-empty and consists only of ASCII [a-zA-Z0-9_].
func isValidHandle(h string) bool {
	if len(h) == 0 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		isLower := c >= 'a' && c <= 'z'
		isUpper := c >= 'A' && c <= 'Z'
		isDigit := c >= '0' && c <= '9'
		if !isLower && !isUpper && !isDigit && c != '_' {
			return false
		}
	}
	return true
}

// loadPWFile reads and validates a JSONL password file.
func loadPWFile(path string) (map[string]PWFileEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open pwfile %q: %w", path, err)
	}
	defer f.Close()

	users := make(map[string]PWFileEntry)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry PWFileEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("pwfile %q line %d: invalid JSON: %w", path, lineNum, err)
		}
		if !isValidHandle(entry.Handle) {
			return nil, fmt.Errorf("pwfile %q line %d: invalid handle %q (must match ASCII [a-z0-9_]+)", path, lineNum, entry.Handle)
		}
		entry.Handle = strings.ToLower(entry.Handle)
		entry.PWHash = strings.ToLower(strings.TrimSpace(entry.PWHash))
		if entry.PW == "" && entry.PWHash == "" {
			return nil, fmt.Errorf("pwfile %q line %d: handle %q must specify 'pw' or 'pwhash'", path, lineNum, entry.Handle)
		}
		users[entry.Handle] = entry
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading pwfile %q: %w", path, err)
	}
	return users, nil
}

// newSite initializes a Site from a SiteConfig and optional site directory.
func newSite(handle, siteDir string, siteCfg SiteConfig) (*Site, error) {
	var pwFilePath string
	pwUsers := make(map[string]PWFileEntry)

	if siteDir != "" {
		pwFilePath = filepath.Join(siteDir, SitePWFilename)
		if _, err := os.Stat(pwFilePath); err == nil {
			var loadErr error
			pwUsers, loadErr = loadPWFile(pwFilePath)
			if loadErr != nil {
				return nil, loadErr
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to stat pwfile %q: %w", pwFilePath, err)
		}
	}

	st, err := NewStore(siteDir)
	if err != nil {
		return nil, fmt.Errorf("site %q store initialization failed: %w", handle, err)
	}

	return &Site{
		handle:     handle,
		dir:        siteDir,
		cfg:        siteCfg,
		pwFilePath: pwFilePath,
		pwUsers:    pwUsers,
		store:      st,
	}, nil
}

// loadSiteFromDir reads <siteDir>/config.json and initializes the Site.
func loadSiteFromDir(handle, siteDir string) (*Site, error) {
	cfgPath := filepath.Join(siteDir, SiteConfigFilename)
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read site config %q: %w", cfgPath, err)
	}
	var siteCfg SiteConfig
	if len(strings.TrimSpace(string(data))) > 0 {
		if err := json.Unmarshal(data, &siteCfg); err != nil {
			return nil, fmt.Errorf("invalid site config %q: %w", cfgPath, err)
		}
	}
	return newSite(handle, siteDir, siteCfg)
}

// AddPWUser adds a new user with a plaintext password to the site's in-memory map
// and appends the JSONL line to the site's pwfile.jsonl (if backed by a directory).
func (site *Site) AddPWUser(handle, display, pw string) error {
	handle = strings.ToLower(strings.TrimSpace(handle))
	display = strings.TrimSpace(display)
	if !isValidHandle(handle) {
		return fmt.Errorf("invalid handle %q (must match ASCII [a-z0-9_]+)", handle)
	}
	if pw == "" {
		return fmt.Errorf("password must not be empty")
	}

	site.pwMu.Lock()
	defer site.pwMu.Unlock()

	if site.pwUsers == nil {
		site.pwUsers = make(map[string]PWFileEntry)
	}
	if _, exists := site.pwUsers[handle]; exists {
		return fmt.Errorf("user handle %q already exists", handle)
	}

	entry := PWFileEntry{
		Handle:  handle,
		Display: display,
		PW:      pw,
	}

	if site.pwFilePath != "" {
		lineBytes, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal user entry: %w", err)
		}

		needLeadingNewline := false
		if data, err := os.ReadFile(site.pwFilePath); err == nil && len(data) > 0 {
			if data[len(data)-1] != '\n' {
				needLeadingNewline = true
			}
		}

		f, err := os.OpenFile(site.pwFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("failed to open pwfile for appending: %w", err)
		}
		defer f.Close()

		var toWrite []byte
		if needLeadingNewline {
			toWrite = append(toWrite, '\n')
		}
		toWrite = append(toWrite, lineBytes...)
		toWrite = append(toWrite, '\n')

		if _, err := f.Write(toWrite); err != nil {
			return fmt.Errorf("failed to append to pwfile: %w", err)
		}
	}

	site.pwUsers[handle] = entry
	return nil
}

// SetPWUserDisabled marks a user in the site's pwfile.jsonl as disabled (or enabled).
func (site *Site) SetPWUserDisabled(handle string, disabled bool) error {
	handle = strings.ToLower(strings.TrimSpace(handle))
	site.pwMu.Lock()
	defer site.pwMu.Unlock()

	entry, exists := site.pwUsers[handle]
	if !exists {
		return ErrNotFound
	}
	entry.Disabled = disabled
	site.pwUsers[handle] = entry

	if site.pwFilePath == "" {
		return nil
	}

	raw, err := os.ReadFile(site.pwFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read pwfile: %w", err)
	}
	var outLines []string
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var item PWFileEntry
		if err := json.Unmarshal([]byte(trimmed), &item); err == nil && strings.ToLower(item.Handle) == handle {
			updatedBytes, err := json.Marshal(entry)
			if err != nil {
				return err
			}
			outLines = append(outLines, string(updatedBytes))
		} else {
			outLines = append(outLines, trimmed)
		}
	}
	newContent := strings.Join(outLines, "\n") + "\n"
	tmpPath := site.pwFilePath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(newContent), 0600); err != nil {
		return fmt.Errorf("failed to write temp pwfile: %w", err)
	}
	return os.Rename(tmpPath, site.pwFilePath)
}

// listPWUsers returns all users from the site's pwfile sorted by handle.
func (site *Site) listPWUsers() []PWFileEntry {
	site.pwMu.RLock()
	defer site.pwMu.RUnlock()

	list := make([]PWFileEntry, 0, len(site.pwUsers))
	for _, u := range site.pwUsers {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Handle < list[j].Handle
	})
	return list
}

// New creates and initializes a new multi-site stardate Server.
func New(cfg ServerConfig) (*Server, error) {
	if cfg.HTTPSAddr != "" && cfg.Addr == "" {
		cfg.Addr = cfg.HTTPSAddr
	}
	if cfg.Addr == "" && cfg.HTTPAddr == "" {
		cfg.Addr = ":8443"
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 10 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 10 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 60 * time.Second
	}

	sites := make(map[string]*Site)

	// 1. Scan subdirectories in cfg.Dir that contain config.json
	if cfg.Dir != "" {
		entries, err := os.ReadDir(cfg.Dir)
		if err != nil {
			return nil, fmt.Errorf("failed to read sites directory %q: %w", cfg.Dir, err)
		}
		for _, entry := range entries {
			if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			siteDir := filepath.Join(cfg.Dir, entry.Name())
			cfgPath := filepath.Join(siteDir, SiteConfigFilename)
			if info, err := os.Stat(cfgPath); err == nil && !info.IsDir() {
				handle := NormalizeSiteHandle(entry.Name())
				if !isValidSiteHandle(handle) {
					continue
				}
				site, err := loadSiteFromDir(handle, siteDir)
				if err != nil {
					return nil, err
				}
				sites[handle] = site
			}
		}
	}

	// 2. Load any explicitly configured sites from cfg.Sites
	for rawHandle, siteCfg := range cfg.Sites {
		handle := NormalizeSiteHandle(rawHandle)
		if !isValidSiteHandle(handle) {
			return nil, fmt.Errorf("invalid site handle %q", rawHandle)
		}
		var siteDir string
		if cfg.Dir != "" {
			candidate := filepath.Join(cfg.Dir, handle)
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				siteDir = candidate
			}
		}
		site, err := newSite(handle, siteDir, siteCfg)
		if err != nil {
			return nil, err
		}
		sites[handle] = site
	}

	tmpl, err := template.New("index").Parse(indexHTML)
	if err != nil {
		return nil, fmt.Errorf("template parsing failed: %w", err)
	}

	s := &Server{
		cfg:   cfg,
		sites: sites,
		tmpl:  tmpl,
	}

	if cfg.Addr != "" {
		certHosts := append([]string(nil), cfg.Hosts...)
		if len(certHosts) == 0 {
			certHosts = []string{"localhost", "127.0.0.1", "::1"}
		}
		for h := range sites {
			certHosts = append(certHosts, h)
		}
		tlsCert, err := LoadOrGenerateCert(cfg.CertFile, cfg.KeyFile, certHosts)
		if err != nil {
			return nil, fmt.Errorf("certificate setup failed: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		}

		s.httpServer = &http.Server{
			Addr:         cfg.Addr,
			Handler:      s,
			TLSConfig:    tlsConfig,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		}
	}

	if cfg.HTTPAddr != "" {
		s.httpPlainServer = &http.Server{
			Addr:         cfg.HTTPAddr,
			Handler:      s,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		}
	}

	return s, nil
}

// Site returns the Site for the given handle (or nil if not found).
func (s *Server) Site(handle string) *Site {
	site, _ := s.getSite(NormalizeSiteHandle(handle))
	return site
}

// getSite looks up a site by normalized handle, lazily loading from <Dir>/<handle>/config.json if present on disk.
func (s *Server) getSite(handle string) (*Site, bool) {
	if !isValidSiteHandle(handle) {
		return nil, false
	}

	s.sitesMu.RLock()
	site, ok := s.sites[handle]
	s.sitesMu.RUnlock()
	if ok {
		return site, true
	}

	if s.cfg.Dir == "" {
		return nil, false
	}

	siteDir := filepath.Join(s.cfg.Dir, handle)
	cfgPath := filepath.Join(siteDir, SiteConfigFilename)
	info, err := os.Stat(cfgPath)
	if err != nil || info.IsDir() {
		return nil, false
	}

	s.sitesMu.Lock()
	defer s.sitesMu.Unlock()
	if site, ok := s.sites[handle]; ok {
		return site, true
	}
	loaded, err := loadSiteFromDir(handle, siteDir)
	if err != nil {
		log.Printf("error loading site %q from %q: %v", handle, siteDir, err)
		return nil, false
	}
	s.sites[handle] = loaded
	return loaded, true
}

// Addr returns the bound HTTPS address of the server.
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.cfg.Addr
}

// HTTPAddr returns the bound HTTP address of the server.
func (s *Server) HTTPAddr() string {
	if s.httpListener != nil {
		return s.httpListener.Addr().String()
	}
	return s.cfg.HTTPAddr
}

// Start runs the HTTPS and/or HTTP servers. It blocks until the servers shut down or error.
func (s *Server) Start() error {
	var tlsListener net.Listener
	if s.httpServer != nil {
		ln, err := net.Listen("tcp", s.cfg.Addr)
		if err != nil {
			return fmt.Errorf("failed to listen on HTTPS %s: %w", s.cfg.Addr, err)
		}
		s.listener = ln
		tlsListener = tls.NewListener(ln, s.httpServer.TLSConfig)
		log.Printf("Stardate server listening securely on https://%s", ln.Addr().String())
	}

	if s.httpPlainServer != nil {
		httpLn, err := net.Listen("tcp", s.cfg.HTTPAddr)
		if err != nil {
			if s.listener != nil {
				_ = s.listener.Close()
			}
			return fmt.Errorf("failed to listen on HTTP %s: %w", s.cfg.HTTPAddr, err)
		}
		s.httpListener = httpLn
		log.Printf("Stardate server listening for testing on http://%s", httpLn.Addr().String())
	}

	errChan := make(chan error, 2)
	active := 0

	if s.httpServer != nil {
		active++
		go func() {
			if err := s.httpServer.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("https server error: %w", err)
			} else {
				errChan <- nil
			}
		}()
	}

	if s.httpPlainServer != nil {
		active++
		go func() {
			if err := s.httpPlainServer.Serve(s.httpListener); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("http server error: %w", err)
			} else {
				errChan <- nil
			}
		}()
	}

	for i := 0; i < active; i++ {
		if err := <-errChan; err != nil {
			return err
		}
	}
	return nil
}

// Shutdown gracefully shuts down the HTTPS and HTTP servers without interrupting active connections.
func (s *Server) Shutdown(ctx context.Context) error {
	var firstErr error
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.httpPlainServer != nil {
		if err := s.httpPlainServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Authenticate verifies HTTP Basic Authentication credentials for this site.
// If the user has explicitly logged out, it treats them as unauthenticated.
func (site *Site) Authenticate(r *http.Request) (*AuthUser, bool) {
	if c, err := r.Cookie("stardate_logout"); err == nil && c.Value == "1" {
		return nil, false
	}
	return site.checkCredentials(r)
}

// isValidCryptoExtra checks that extra is "/" followed by at least 12 ASCII characters.
func isValidCryptoExtra(extra string) bool {
	if len(extra) < 13 || extra[0] != '/' {
		return false
	}
	secretPart := extra[1:]
	for i := 0; i < len(secretPart); i++ {
		if secretPart[i] > 127 {
			return false
		}
	}
	return true
}

// matchPWEntry checks whether pass matches the PWFileEntry (via plaintext pw or pwhash),
// returning the trailing extra suffix (empty for standard login, or "/..." for crypto login).
func matchPWEntry(salt string, entry PWFileEntry, pass string) (string, bool) {
	if entry.PW != "" {
		pwLen := len(entry.PW)
		if len(pass) >= pwLen && subtle.ConstantTimeCompare([]byte(pass[:pwLen]), []byte(entry.PW)) == 1 {
			return pass[pwLen:], true
		}
	}
	if entry.PWHash != "" {
		if subtle.ConstantTimeCompare([]byte(HashPassword(salt, pass)), []byte(entry.PWHash)) == 1 {
			return "", true
		}
		for i := 0; i < len(pass); i++ {
			if pass[i] == '/' {
				if subtle.ConstantTimeCompare([]byte(HashPassword(salt, pass[:i])), []byte(entry.PWHash)) == 1 {
					return pass[i:], true
				}
			}
		}
	}
	return "", false
}

// checkCredentials validates HTTP Basic Auth credentials against the site's pwfile.jsonl entries first,
// and falls back to the site's shared password (pw) if non-empty.
// For crypto users, the password must be BasePassword + "/" + at least 12 ASCII characters,
// or else the credentials are rejected.
func (site *Site) checkCredentials(r *http.Request) (*AuthUser, bool) {
	user, pass, ok := r.BasicAuth()
	if !ok || strings.TrimSpace(user) == "" {
		return nil, false
	}
	user = strings.TrimSpace(user)

	// 1. Check pwfile users if present and handle is valid ASCII [a-z0-9_]+
	if isValidHandle(user) {
		normHandle := strings.ToLower(user)
		site.pwMu.RLock()
		entry, exists := site.pwUsers[normHandle]
		site.pwMu.RUnlock()
		if exists {
			if entry.Disabled {
				return nil, false
			}
			extra, matched := matchPWEntry(site.cfg.Salt, entry, pass)
			if !matched {
				return nil, false
			}
			if extra == "" {
				effUser := entry.Handle
				if entry.Display != "" {
					effUser = entry.Display
				}
				return &AuthUser{
					Username:      entry.Handle,
					EffectiveUser: effUser,
					IsCrypto:      false,
					IsSuperuser:   entry.Superuser,
				}, true
			}
			if !isValidCryptoExtra(extra) {
				return nil, false
			}
			cryptoUser, key := DeriveCryptoIdentity(site.cfg.Salt, entry.Handle, pass)
			return &AuthUser{
				Username:       entry.Handle,
				CryptoUsername: cryptoUser,
				EffectiveUser:  cryptoUser,
				CryptoKey:      key,
				IsCrypto:       true,
				IsSuperuser:    entry.Superuser,
			}, true
		}
	}

	// 2. Fallback to shared password (pw) if non-empty
	if site.cfg.Password == "" {
		return nil, false
	}

	pwLen := len(site.cfg.Password)
	if len(pass) < pwLen {
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(pass[:pwLen]), []byte(site.cfg.Password)) != 1 {
		return nil, false
	}

	extra := pass[pwLen:]
	if extra == "" {
		return &AuthUser{
			Username:      user,
			EffectiveUser: user,
			IsCrypto:      false,
		}, true
	}

	if !isValidCryptoExtra(extra) {
		return nil, false
	}

	cryptoUser, key := DeriveCryptoIdentity(site.cfg.Salt, user, pass)
	return &AuthUser{
		Username:       user,
		CryptoUsername: cryptoUser,
		EffectiveUser:  cryptoUser,
		CryptoKey:      key,
		IsCrypto:       true,
	}, true
}

// CalculateStardate computes a stardate value for the given time.
// Standard modern era convention: (Year - 2000) * 1000 + (fraction of year * 1000).
func CalculateStardate(t time.Time) float64 {
	utc := t.UTC()
	year := utc.Year()
	startOfYear := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
	startOfNextYear := time.Date(year+1, 1, 1, 0, 0, 0, 0, time.UTC)

	totalSeconds := startOfNextYear.Sub(startOfYear).Seconds()
	elapsedSeconds := utc.Sub(startOfYear).Seconds()

	fraction := elapsedSeconds / totalSeconds
	return float64(year-2000)*1000.0 + fraction*1000.0
}

type pageMessage struct {
	ID             int64
	Author         string
	Flavor         string
	Title          string
	Images         []string
	ImagesCSV      string
	Attachments    []string
	AttachmentsCSV string
	IsStarred      bool
	Content        string
	RenderedHTML   template.HTML
	SummaryHTML    template.HTML
	HasMore        bool
	Format         string
	IsPublic       bool
	CanEdit        bool
	CanHide        bool
	Stardate       string
	UTC            string
}

type pageData struct {
	BasePath        string
	SiteTitle       string
	HideStardates   bool
	SinglePost      bool
	LoggedIn        bool
	User            string
	IsCrypto        bool
	IsSuperuser     bool
	ShowDashboard   bool
	PWUsers         []PWFileEntry
	CurrentStardate string
	CurrentUTC      string
	StarredItems    []pageMessage
	Messages        []pageMessage
}

// ServeHTTP routes incoming requests by `/@<site>/...` URL override or HTTP/HTTPS Hostname (with leading "www." trimmed).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path
	if urlPath == "" {
		urlPath = "/"
	}

	var siteHandle, basePath, subPath string
	if strings.HasPrefix(urlPath, "/@") {
		rest := strings.TrimPrefix(urlPath, "/@")
		slashIdx := strings.IndexByte(rest, '/')
		var rawSite string
		if slashIdx == -1 {
			rawSite = rest
			subPath = "/"
		} else {
			rawSite = rest[:slashIdx]
			subPath = rest[slashIdx:]
		}
		if rawSite == "" {
			http.NotFound(w, r)
			return
		}
		siteHandle = NormalizeSiteHandle(rawSite)
		basePath = "/@" + rawSite
	} else {
		// Global endpoints that do not require a site match when called at top level
		switch urlPath {
		case "/healthz":
			s.handleHealthz(w, r)
			return
		case "/static/quill.js":
			s.handleStaticQuillJS(w, r)
			return
		case "/static/quill.snow.css":
			s.handleStaticQuillCSS(w, r)
			return
		}
		siteHandle = NormalizeSiteHandle(r.Host)
		basePath = ""
		subPath = urlPath
	}

	switch subPath {
	case "/healthz":
		s.handleHealthz(w, r)
		return
	case "/static/quill.js":
		s.handleStaticQuillJS(w, r)
		return
	case "/static/quill.snow.css":
		s.handleStaticQuillCSS(w, r)
		return
	}

	site, ok := s.getSite(siteHandle)
	if !ok {
		http.NotFound(w, r)
		return
	}

	if strings.HasPrefix(subPath, "/images/") {
		s.handleSiteMedia(site, DirImages, strings.TrimPrefix(subPath, "/images/"), w, r)
		return
	}
	if strings.HasPrefix(subPath, "/attachments/") {
		s.handleSiteMedia(site, DirAttachments, strings.TrimPrefix(subPath, "/attachments/"), w, r)
		return
	}

	switch subPath {
	case "/", "/stardate":
		s.handleSiteRoot(site, basePath, w, r)
	case "/login":
		s.handleSiteLogin(site, basePath, w, r)
	case "/logout":
		s.handleSiteLogout(site, basePath, w, r)
	case "/post":
		s.handleSitePost(site, basePath, w, r)
	case "/hide":
		s.handleSiteHide(site, basePath, w, r)
	case "/users":
		s.handleSiteAddUser(site, basePath, w, r)
	case "/users/disable":
		s.handleSiteDisableUser(site, basePath, w, r)
	default:
		trimmed := strings.TrimPrefix(subPath, "/")
		if trimmed != "" && !strings.Contains(trimmed, "/") {
			if postID, err := strconv.ParseInt(trimmed, 10, 64); err == nil && postID > 0 {
				s.handleSiteSinglePost(site, basePath, postID, w, r)
				return
			}
		}
		http.NotFound(w, r)
	}
}

func (s *Server) handleSiteMedia(site *Site, kindDir, relPath string, w http.ResponseWriter, r *http.Request) {
	if site.dir == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimSpace(relPath), "/"), "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	postID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || postID <= 0 {
		http.NotFound(w, r)
		return
	}
	fileName := strings.TrimSpace(parts[1])
	if fileName == "" || fileName == "." || fileName == ".." || filepath.Base(fileName) != fileName || strings.ContainsAny(fileName, `/\`) {
		http.NotFound(w, r)
		return
	}

	m, ok := site.store.GetRAMByID(postID)
	if !ok || m.Hidden {
		http.NotFound(w, r)
		return
	}
	if !m.IsPublic {
		auth, loggedIn := site.Authenticate(r)
		if !loggedIn || auth.EffectiveUser != m.Author {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}

	mediaPath := filepath.Join(site.dir, kindDir, strconv.FormatInt(postID, 10), fileName)
	info, err := os.Stat(mediaPath)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, mediaPath)
}

func sanitizeFilename(name string) string {
	base := filepath.Base(strings.TrimSpace(name))
	var b strings.Builder
	for i := 0; i < len(base); i++ {
		c := base[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' {
			b.WriteByte(c)
		} else {
			b.WriteByte('_')
		}
	}
	res := strings.Trim(b.String(), "._")
	if res == "" {
		res = "file.bin"
	}
	return res
}

func saveUploadedFiles(site *Site, kindDir string, postID int64, files []*multipart.FileHeader) ([]string, error) {
	var saved []string
	for _, fh := range files {
		if fh == nil || fh.Size == 0 {
			continue
		}
		cleanName := sanitizeFilename(fh.Filename)
		savedName := cleanName
		if site.dir != "" {
			postMediaDir := filepath.Join(site.dir, kindDir, strconv.FormatInt(postID, 10))
			if err := os.MkdirAll(postMediaDir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create %s directory: %w", kindDir, err)
			}
			destPath := filepath.Join(postMediaDir, savedName)
			if _, err := os.Stat(destPath); err == nil {
				savedName = fmt.Sprintf("%d_%s", time.Now().UnixNano(), cleanName)
				destPath = filepath.Join(postMediaDir, savedName)
			}
			src, err := fh.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open uploaded file: %w", err)
			}
			dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				_ = src.Close()
				return nil, fmt.Errorf("failed to save uploaded file: %w", err)
			}
			_, copyErr := io.Copy(dst, src)
			_ = dst.Close()
			_ = src.Close()
			if copyErr != nil {
				return nil, fmt.Errorf("failed to write uploaded file: %w", copyErr)
			}
		}
		saved = append(saved, savedName)
	}
	return saved, nil
}

func parseCSVFilenames(csv string) []string {
	var list []string
	for _, part := range strings.Split(strings.TrimSpace(csv), ",") {
		p := strings.TrimSpace(part)
		if p != "" && p != "." && p != ".." && filepath.Base(p) == p && !strings.ContainsAny(p, `/\`) {
			list = append(list, p)
		}
	}
	return list
}

var dataImgSrcRe = regexp.MustCompile(`(?i)src=["']data:image/(png|jpeg|jpg|gif|webp);base64,([A-Za-z0-9+/=\s]+)["']`)

func rewriteHTMLImageBasePath(htmlContent, basePath string) string {
	if basePath == "" || !strings.Contains(htmlContent, "/images/") {
		return htmlContent
	}
	res := strings.ReplaceAll(htmlContent, `src="/images/`, `src="`+basePath+`/images/`)
	res = strings.ReplaceAll(res, `src='/images/`, `src='`+basePath+`/images/`)
	return res
}

func extractInlineDataImages(site *Site, basePath string, postID int64, htmlContent string) (string, error) {
	if basePath != "" {
		htmlContent = strings.ReplaceAll(htmlContent, `src="`+basePath+`/images/`, `src="/images/`)
		htmlContent = strings.ReplaceAll(htmlContent, `src='`+basePath+`/images/`, `src='/images/`)
	}
	if !dataImgSrcRe.MatchString(htmlContent) {
		return htmlContent, nil
	}

	var firstErr error
	imgIdx := 0
	replaced := dataImgSrcRe.ReplaceAllStringFunc(htmlContent, func(match string) string {
		if firstErr != nil {
			return match
		}
		sub := dataImgSrcRe.FindStringSubmatch(match)
		if len(sub) < 3 {
			return match
		}
		imgIdx++
		ext := strings.ToLower(sub[1])
		if ext == "jpeg" {
			ext = "jpg"
		}
		b64Clean := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
				return -1
			}
			return r
		}, sub[2])

		rawBytes, err := base64.StdEncoding.DecodeString(b64Clean)
		if err != nil {
			rawBytes, err = base64.RawStdEncoding.DecodeString(b64Clean)
			if err != nil {
				firstErr = fmt.Errorf("invalid base64 inline image: %w", err)
				return match
			}
		}

		savedName := fmt.Sprintf("inline_%d.%s", imgIdx, ext)
		if site.dir != "" {
			postImgDir := filepath.Join(site.dir, DirImages, strconv.FormatInt(postID, 10))
			if err := os.MkdirAll(postImgDir, 0755); err != nil {
				firstErr = fmt.Errorf("failed to create images directory: %w", err)
				return match
			}
			destPath := filepath.Join(postImgDir, savedName)
			if _, err := os.Stat(destPath); err == nil {
				savedName = fmt.Sprintf("inline_%d_%d.%s", imgIdx, time.Now().UnixNano(), ext)
				destPath = filepath.Join(postImgDir, savedName)
			}
			if err := os.WriteFile(destPath, rawBytes, 0644); err != nil {
				firstErr = fmt.Errorf("failed to save inline image: %w", err)
				return match
			}
		}
		return fmt.Sprintf(`src="/images/%d/%s"`, postID, savedName)
	})

	if firstErr != nil {
		return htmlContent, firstErr
	}
	return replaced, nil
}

func buildPageMessage(m Message, basePath string, loggedIn, isSuperuser bool, effectiveUser string, singleView bool) pageMessage {
	fmtNorm := NormalizeFormat(m.Format)
	flavNorm := NormalizeFlavor(m.Flavor)
	canEdit := loggedIn && (m.Author == effectiveUser || (isSuperuser && m.IsPublic))
	contentForView := m.Content
	if fmtNorm == FormatHTML {
		contentForView = rewriteHTMLImageBasePath(contentForView, basePath)
	}
	renderedHTML := RenderAndSanitize(contentForView, fmtNorm)
	summaryHTML := renderedHTML
	hasMore := m.HasMore
	if !singleView && flavNorm == FlavorArticle {
		var extractedMore bool
		summaryHTML, extractedMore = ExtractArticleFirstParagraph(contentForView, fmtNorm)
		if extractedMore {
			hasMore = true
		}
	}
	return pageMessage{
		ID:             m.ID,
		Author:         m.Author,
		Flavor:         flavNorm,
		Title:          m.Title,
		Images:         m.Images,
		ImagesCSV:      strings.Join(m.Images, ","),
		Attachments:    m.Attachments,
		AttachmentsCSV: strings.Join(m.Attachments, ","),
		IsStarred:      m.IsStarred && (flavNorm == FlavorArticle || flavNorm == FlavorGallery),
		Content:        contentForView,
		RenderedHTML:   renderedHTML,
		SummaryHTML:    summaryHTML,
		HasMore:        hasMore,
		Format:         fmtNorm,
		IsPublic:       m.IsPublic,
		CanEdit:        canEdit,
		CanHide:        isSuperuser,
		Stardate:       fmt.Sprintf("%.2f", m.Stardate),
		UTC:            m.CreatedAt.Format("2006-01-02 15:04:05 UTC"),
	}
}

func (s *Server) handleSiteSinglePost(site *Site, basePath string, postID int64, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	m, ok := site.store.GetByID(postID)
	if !ok || m.Hidden {
		http.NotFound(w, r)
		return
	}

	auth, loggedIn := site.Authenticate(r)
	var effectiveUser string
	if loggedIn {
		effectiveUser = auth.EffectiveUser
	}

	if !m.IsPublic && (!loggedIn || effectiveUser != m.Author) {
		http.NotFound(w, r)
		return
	}

	m.Flavor = NormalizeFlavor(m.Flavor)
	if m.Flavor == FlavorLog {
		m.IsStarred = false
	}
	if !m.IsPublic && loggedIn && auth.IsCrypto && m.Author == effectiveUser {
		if decrypted, err := DecryptMessage(m.Content, auth.CryptoKey); err == nil {
			m.Content = decrypted
		}
		if m.Title != "" {
			if decTitle, err := DecryptMessage(m.Title, auth.CryptoKey); err == nil {
				m.Title = decTitle
			}
		}
	}

	if NormalizeFormat(m.Format) == FormatHTML {
		m.Content = rewriteHTMLImageBasePath(m.Content, basePath)
	}

	if r.URL.Query().Get("format") == "json" || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(m)
		return
	}

	now := time.Now().UTC()
	sd := CalculateStardate(now)
	isSuperuser := loggedIn && auth.IsSuperuser
	pm := buildPageMessage(m, basePath, loggedIn, isSuperuser, effectiveUser, true)

	siteTitle := site.cfg.SiteTitle
	if siteTitle == "" {
		siteTitle = "Stardate"
	}

	data := pageData{
		BasePath:        basePath,
		SiteTitle:       siteTitle,
		HideStardates:   site.cfg.HideStardates,
		SinglePost:      true,
		LoggedIn:        loggedIn,
		User:            effectiveUser,
		IsCrypto:        loggedIn && auth.IsCrypto,
		IsSuperuser:     isSuperuser,
		CurrentStardate: fmt.Sprintf("%.2f", sd),
		CurrentUTC:      now.Format(time.RFC3339),
		Messages:        []pageMessage{pm},
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, data); err != nil {
		log.Printf("template render error: %v", err)
	}
}

func (s *Server) handleSiteRoot(site *Site, basePath string, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	auth, loggedIn := site.Authenticate(r)
	var viewer string
	if loggedIn {
		viewer = auth.EffectiveUser
	}

	recentMsgs := site.store.GetRecent(viewer, 100)

	// Decrypt any private messages belonging to this crypto user
	displayMsgs := make([]Message, len(recentMsgs))
	for i, m := range recentMsgs {
		m.Flavor = NormalizeFlavor(m.Flavor)
		if m.Flavor == FlavorLog {
			m.IsStarred = false
		}
		displayMsgs[i] = m
		if !m.IsPublic && loggedIn && auth.IsCrypto && m.Author == auth.EffectiveUser {
			if decrypted, err := DecryptMessage(m.Content, auth.CryptoKey); err == nil {
				displayMsgs[i].Content = decrypted
			}
			if m.Title != "" {
				if decTitle, err := DecryptMessage(m.Title, auth.CryptoKey); err == nil {
					displayMsgs[i].Title = decTitle
				}
			}
		}
	}

	now := time.Now().UTC()
	sd := CalculateStardate(now)

	wantsJSON := r.URL.Query().Get("format") == "json" ||
		strings.Contains(r.Header.Get("Accept"), "application/json")

	if wantsJSON {
		userStr := ""
		isCrypto := false
		isSuper := false
		if loggedIn {
			userStr = auth.EffectiveUser
			isCrypto = auth.IsCrypto
			isSuper = auth.IsSuperuser
		}
		res := StardateResponse{
			Site:        site.handle,
			User:        userStr,
			IsCrypto:    isCrypto,
			IsSuperuser: isSuper,
			Stardate:    sd,
			Formatted:   fmt.Sprintf("%.2f", sd),
			UTC:         now.Format(time.RFC3339),
			Timestamp:   now.Unix(),
			Messages:    displayMsgs,
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(res)
		return
	}

	isSuperuser := loggedIn && auth.IsSuperuser
	viewMsgs := make([]pageMessage, 0, len(displayMsgs))
	var starredItems []pageMessage
	for _, m := range displayMsgs {
		pm := buildPageMessage(m, basePath, loggedIn, isSuperuser, viewer, false)
		viewMsgs = append(viewMsgs, pm)
		if pm.IsStarred {
			starredItems = append(starredItems, pm)
		}
	}

	userName := ""
	isCrypto := false
	var pwUsers []PWFileEntry
	if loggedIn {
		userName = auth.EffectiveUser
		isCrypto = auth.IsCrypto
		if isSuperuser {
			pwUsers = site.listPWUsers()
		}
	}

	siteTitle := site.cfg.SiteTitle
	if siteTitle == "" {
		siteTitle = "Stardate"
	}

	data := pageData{
		BasePath:        basePath,
		SiteTitle:       siteTitle,
		HideStardates:   site.cfg.HideStardates,
		LoggedIn:        loggedIn,
		User:            userName,
		IsCrypto:        isCrypto,
		IsSuperuser:     isSuperuser,
		ShowDashboard:   isSuperuser && r.URL.Query().Get("dashboard") == "1",
		PWUsers:         pwUsers,
		CurrentStardate: fmt.Sprintf("%.2f", sd),
		CurrentUTC:      now.Format(time.RFC3339),
		StarredItems:    starredItems,
		Messages:        viewMsgs,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, data); err != nil {
		log.Printf("template render error: %v", err)
	}
}

func (s *Server) handleSiteLogin(site *Site, basePath string, w http.ResponseWriter, r *http.Request) {
	hasLogoutCookie := false
	if c, err := r.Cookie("stardate_logout"); err == nil && c.Value == "1" {
		hasLogoutCookie = true
	}

	hasPrompted := false
	if c, err := r.Cookie("stardate_prompted"); err == nil && c.Value == "1" {
		hasPrompted = true
	}

	// If the user previously logged out and hasn't yet been prompted for fresh credentials,
	// issue a 401 challenge so the browser displays the login prompt.
	if hasLogoutCookie && !hasPrompted {
		http.SetCookie(w, &http.Cookie{
			Name:     "stardate_prompted",
			Value:    "1",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		w.Header().Set("WWW-Authenticate", `Basic realm="stardate"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	auth, loggedIn := site.checkCredentials(r)
	if !loggedIn {
		w.Header().Set("WWW-Authenticate", `Basic realm="stardate"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Successful login: clear both logout and prompted cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "stardate_logout",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "stardate_prompted",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	_ = auth
	http.Redirect(w, r, basePath+"/", http.StatusSeeOther)
}

func (s *Server) handleSiteLogout(site *Site, basePath string, w http.ResponseWriter, r *http.Request) {
	_ = site
	http.SetCookie(w, &http.Cookie{
		Name:     "stardate_logout",
		Value:    "1",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "stardate_prompted",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	http.Redirect(w, r, basePath+"/", http.StatusSeeOther)
}

func (s *Server) handleSitePost(site *Site, basePath string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	auth, loggedIn := site.Authenticate(r)
	if !loggedIn {
		w.Header().Set("WWW-Authenticate", `Basic realm="stardate"`)
		http.Error(w, "Login required to post", http.StatusUnauthorized)
		return
	}

	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(strings.ToLower(ct), "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
	}

	flavor := NormalizeFlavor(r.FormValue("flavor"))
	title := strings.TrimSpace(r.FormValue("title"))
	format := NormalizeFormat(r.FormValue("format"))
	rawContent := strings.TrimSpace(r.FormValue("content"))
	hasInlineDataImg := format == FormatHTML && dataImgSrcRe.MatchString(rawContent)
	content := rawContent
	if format == FormatHTML && !hasInlineDataImg {
		if basePath != "" {
			content = strings.ReplaceAll(content, `src="`+basePath+`/images/`, `src="/images/`)
			content = strings.ReplaceAll(content, `src='`+basePath+`/images/`, `src='/images/`)
		}
		content = strings.TrimSpace(htmlPolicy.Sanitize(content))
		if content == "<p><br></p>" || content == "<p></p>" {
			content = ""
		}
	}

	isChecked := func(v string) bool {
		return v == "1" || v == "on" || v == "true"
	}
	isPublic := isChecked(r.FormValue("public1")) && isChecked(r.FormValue("public2"))
	isStarred := (flavor == FlavorArticle || flavor == FlavorGallery) && isChecked(r.FormValue("is_starred"))

	imageList := parseCSVFilenames(r.FormValue("existing_images"))
	attachmentList := parseCSVFilenames(r.FormValue("existing_attachments"))

	var uploadedImages, uploadedAttachments []*multipart.FileHeader
	if r.MultipartForm != nil && r.MultipartForm.File != nil {
		if flavor == FlavorGallery {
			uploadedImages = r.MultipartForm.File["images"]
		} else {
			uploadedAttachments = r.MultipartForm.File["attachments"]
		}
	}

	hasUploadedImages := false
	for _, fh := range uploadedImages {
		if fh != nil && fh.Size > 0 {
			hasUploadedImages = true
			break
		}
	}
	hasUploadedAttachments := false
	for _, fh := range uploadedAttachments {
		if fh != nil && fh.Size > 0 {
			hasUploadedAttachments = true
			break
		}
	}

	if flavor == FlavorLog {
		title = ""
		imageList = nil
		isStarred = false
		if content == "" && !hasInlineDataImg && len(attachmentList) == 0 && !hasUploadedAttachments {
			http.Redirect(w, r, basePath+"/", http.StatusSeeOther)
			return
		}
	} else if flavor == FlavorArticle {
		imageList = nil
		if content == "" && !hasInlineDataImg && title == "" && len(attachmentList) == 0 && !hasUploadedAttachments {
			http.Redirect(w, r, basePath+"/", http.StatusSeeOther)
			return
		}
	} else if flavor == FlavorGallery {
		attachmentList = nil
		if content == "" && !hasInlineDataImg && title == "" && len(imageList) == 0 && !hasUploadedImages {
			http.Redirect(w, r, basePath+"/", http.StatusSeeOther)
			return
		}
	}

	editIDStr := strings.TrimSpace(r.FormValue("edit_id"))
	if editIDStr != "" {
		editID, err := strconv.ParseInt(editIDStr, 10, 64)
		if err != nil || editID <= 0 {
			http.Error(w, "Invalid edit_id", http.StatusBadRequest)
			return
		}
		origMsg, found := site.store.GetByID(editID)
		if !found {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		isOwner := origMsg.Author == auth.EffectiveUser
		if !isOwner && !(auth.IsSuperuser && origMsg.IsPublic) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if r.FormValue("flavor") == "" && origMsg.Flavor != "" {
			flavor = NormalizeFlavor(origMsg.Flavor)
		}
		if flavor == FlavorGallery && len(imageList) == 0 && len(origMsg.Images) > 0 && r.FormValue("existing_images") == "" {
			imageList = origMsg.Images
		}
		if flavor != FlavorGallery && len(attachmentList) == 0 && len(origMsg.Attachments) > 0 && r.FormValue("existing_attachments") == "" {
			attachmentList = origMsg.Attachments
		}

		if format == FormatHTML && hasInlineDataImg {
			extracted, err := extractInlineDataImages(site, basePath, editID, rawContent)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			content = strings.TrimSpace(htmlPolicy.Sanitize(extracted))
			if content == "<p><br></p>" || content == "<p></p>" {
				content = ""
			}
		}

		if len(uploadedImages) > 0 {
			newImgs, err := saveUploadedFiles(site, DirImages, editID, uploadedImages)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			imageList = append(imageList, newImgs...)
		}
		if len(uploadedAttachments) > 0 {
			newAtts, err := saveUploadedFiles(site, DirAttachments, editID, uploadedAttachments)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			attachmentList = append(attachmentList, newAtts...)
		}

		contentToStore := content
		titleToStore := title
		if isOwner && !isPublic && auth.IsCrypto {
			encrypted, err := EncryptMessage(content, auth.CryptoKey)
			if err != nil {
				http.Error(w, "Failed to encrypt private message", http.StatusInternalServerError)
				return
			}
			contentToStore = encrypted
			if title != "" {
				encTitle, err := EncryptMessage(title, auth.CryptoKey)
				if err != nil {
					http.Error(w, "Failed to encrypt private title", http.StatusInternalServerError)
					return
				}
				titleToStore = encTitle
			}
		}

		if _, err := site.store.UpdateEntry(editID, auth.EffectiveUser, auth.IsSuperuser, flavor, titleToStore, imageList, isStarred, contentToStore, format, isPublic); err != nil {
			if errors.Is(err, ErrForbidden) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			if errors.Is(err, ErrNotFound) {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to update message", http.StatusInternalServerError)
			return
		}
		if len(attachmentList) > 0 {
			_, _ = site.store.SetFiles(editID, imageList, attachmentList)
		}
		http.Redirect(w, r, basePath+"/", http.StatusSeeOther)
		return
	}

	initialContent := content
	if hasInlineDataImg {
		initialContent = ""
	}
	contentToStore := initialContent
	titleToStore := title
	if !isPublic && auth.IsCrypto {
		encrypted, err := EncryptMessage(initialContent, auth.CryptoKey)
		if err != nil {
			http.Error(w, "Failed to encrypt private message", http.StatusInternalServerError)
			return
		}
		contentToStore = encrypted
		if title != "" {
			encTitle, err := EncryptMessage(title, auth.CryptoKey)
			if err != nil {
				http.Error(w, "Failed to encrypt private title", http.StatusInternalServerError)
				return
			}
			titleToStore = encTitle
		}
	}

	createdMsg, err := site.store.AddEntry(auth.EffectiveUser, flavor, titleToStore, imageList, isStarred, contentToStore, format, isPublic)
	if err != nil {
		http.Error(w, "Failed to save message", http.StatusInternalServerError)
		return
	}

	if hasInlineDataImg {
		extracted, err := extractInlineDataImages(site, basePath, createdMsg.ID, rawContent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		content = strings.TrimSpace(htmlPolicy.Sanitize(extracted))
		if content == "<p><br></p>" || content == "<p></p>" {
			content = ""
		}
		finalContentToStore := content
		if !isPublic && auth.IsCrypto {
			encrypted, err := EncryptMessage(content, auth.CryptoKey)
			if err != nil {
				http.Error(w, "Failed to encrypt private message", http.StatusInternalServerError)
				return
			}
			finalContentToStore = encrypted
		}
		if _, err := site.store.UpdateEntry(createdMsg.ID, auth.EffectiveUser, auth.IsSuperuser, flavor, titleToStore, imageList, isStarred, finalContentToStore, format, isPublic); err != nil {
			http.Error(w, "Failed to update message with inline images", http.StatusInternalServerError)
			return
		}
	}

	if len(uploadedImages) > 0 {
		newImgs, err := saveUploadedFiles(site, DirImages, createdMsg.ID, uploadedImages)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		imageList = append(imageList, newImgs...)
	}
	if len(uploadedAttachments) > 0 {
		newAtts, err := saveUploadedFiles(site, DirAttachments, createdMsg.ID, uploadedAttachments)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		attachmentList = append(attachmentList, newAtts...)
	}
	if len(imageList) > 0 || len(attachmentList) > 0 {
		if _, err := site.store.SetFiles(createdMsg.ID, imageList, attachmentList); err != nil {
			http.Error(w, "Failed to update post files", http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, basePath+"/", http.StatusSeeOther)
}

func (s *Server) handleSiteHide(site *Site, basePath string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	auth, loggedIn := site.Authenticate(r)
	if !loggedIn {
		w.Header().Set("WWW-Authenticate", `Basic realm="stardate"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !auth.IsSuperuser {
		http.Error(w, "Forbidden: superuser required", http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "Invalid message id", http.StatusBadRequest)
		return
	}

	if _, err := site.store.SetHidden(id, true); err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to hide message", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, basePath+"/", http.StatusSeeOther)
}

func (s *Server) handleSiteAddUser(site *Site, basePath string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	auth, loggedIn := site.Authenticate(r)
	if !loggedIn {
		w.Header().Set("WWW-Authenticate", `Basic realm="stardate"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !auth.IsSuperuser {
		http.Error(w, "Forbidden: superuser required", http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	handle := r.FormValue("handle")
	display := r.FormValue("display")
	pw := r.FormValue("pw")

	if err := site.AddPWUser(handle, display, pw); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, basePath+"/?dashboard=1", http.StatusSeeOther)
}

func (s *Server) handleSiteDisableUser(site *Site, basePath string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	auth, loggedIn := site.Authenticate(r)
	if !loggedIn {
		w.Header().Set("WWW-Authenticate", `Basic realm="stardate"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !auth.IsSuperuser {
		http.Error(w, "Forbidden: superuser required", http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	handle := r.FormValue("handle")
	disabledVal := strings.TrimSpace(r.FormValue("disabled"))
	disabled := disabledVal != "0" && disabledVal != "false"

	if err := site.SetPWUserDisabled(handle, disabled); err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, basePath+"/?dashboard=1", http.StatusSeeOther)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.SiteTitle}} Log</title>
  {{if .LoggedIn}}<link rel="stylesheet" href="/static/quill.snow.css">{{end}}
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #141c2e;
      --border: #23314d;
      --text: #e2e8f0;
      --muted: #8b9bb4;
      --accent: #38bdf8;
      --accent-hover: #0ea5e9;
      --private-color: #f59e0b;
      --public-color: #10b981;
      --crypto-color: #a855f7;
      --danger-color: #ef4444;
      --star-color: #fbbf24;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 1.5rem 1rem;
      display: flex;
      justify-content: center;
    }
    .container { width: 100%; max-width: 680px; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.5rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
      flex-wrap: wrap;
      gap: 0.75rem;
    }
    .brand h1 { font-size: 1.4rem; color: var(--accent); letter-spacing: 0.5px; }
    .brand .stardate-live { font-size: 0.85rem; color: var(--muted); font-family: monospace; }
    .nav-actions { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
    .btn {
      display: inline-block;
      padding: 0.4rem 0.85rem;
      border-radius: 6px;
      font-size: 0.85rem;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
      border: 1px solid transparent;
      transition: background 0.15s, opacity 0.15s;
    }
    .btn-primary { background: var(--accent); color: #0b0f19; border-color: var(--accent); }
    .btn-primary:hover { background: var(--accent-hover); }
    .btn-outline { background: transparent; color: var(--text); border-color: var(--border); }
    .btn-outline:hover { background: var(--border); }
    .btn-muted { background: transparent; color: var(--muted); }
    .btn-muted:hover { color: var(--text); }
    .btn-edit {
      background: transparent;
      color: var(--accent);
      border: 1px solid rgba(56, 189, 248, 0.35);
      border-radius: 4px;
      padding: 0.12rem 0.45rem;
      font-size: 0.7rem;
      font-weight: 600;
      cursor: pointer;
      margin-right: 0.3rem;
    }
    .btn-edit:hover {
      background: rgba(56, 189, 248, 0.15);
    }
    .btn-hide {
      background: transparent;
      color: var(--danger-color);
      border: 1px solid rgba(239, 68, 68, 0.35);
      border-radius: 4px;
      padding: 0.12rem 0.45rem;
      font-size: 0.7rem;
      font-weight: 600;
      cursor: pointer;
      margin-right: 0.3rem;
    }
    .btn-hide:hover {
      background: rgba(239, 68, 68, 0.15);
    }
    .inline-form { display: block; margin: 0; }
    .dropdown-menu {
      position: relative;
      display: inline-block;
      margin-left: 0.35rem;
    }
    .dropdown-trigger {
      list-style: none;
      cursor: pointer;
      color: var(--muted);
      background: transparent;
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 0.1rem 0.4rem;
      font-size: 0.7rem;
      line-height: 1.2;
      user-select: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      transition: color 0.15s, border-color 0.15s, background 0.15s;
    }
    .dropdown-trigger::-webkit-details-marker { display: none; }
    .dropdown-trigger:hover,
    .dropdown-menu[open] .dropdown-trigger {
      color: var(--accent);
      border-color: var(--accent);
      background: rgba(56, 189, 248, 0.1);
    }
    .dropdown-list {
      position: absolute;
      right: 0;
      top: calc(100% + 4px);
      min-width: 135px;
      background: #0b0f19;
      border: 1px solid var(--border);
      border-radius: 6px;
      box-shadow: 0 6px 16px rgba(0, 0, 0, 0.55);
      padding: 0.25rem;
      z-index: 50;
      display: flex;
      flex-direction: column;
      gap: 0.15rem;
    }
    .dropdown-item {
      display: block;
      width: 100%;
      text-align: left;
      background: transparent;
      color: var(--text);
      border: none;
      border-radius: 4px;
      padding: 0.35rem 0.6rem;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
      font-family: inherit;
      white-space: nowrap;
    }
    .dropdown-item:hover {
      background: rgba(56, 189, 248, 0.15);
      color: var(--accent);
    }
    .dropdown-item-danger {
      color: var(--danger-color);
    }
    .dropdown-item-danger:hover {
      background: rgba(239, 68, 68, 0.15);
      color: var(--danger-color);
    }
    .user-tag { font-size: 0.85rem; color: var(--muted); display: flex; align-items: center; gap: 0.4rem; }
    .user-tag strong { color: var(--accent); }
    .compose-box, .dashboard-box, .starred-box {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      margin-bottom: 1.5rem;
    }
    .flavor-chooser-title {
      font-size: 0.95rem;
      font-weight: 600;
      color: var(--text);
      margin-bottom: 0.75rem;
    }
    .flavor-options {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 0.6rem;
      margin-bottom: 0.75rem;
    }
    @media (max-width: 560px) {
      .flavor-options { grid-template-columns: 1fr; }
    }
    .flavor-choice-btn {
      background: #0b0f19;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.85rem 0.65rem;
      color: var(--text);
      cursor: pointer;
      text-align: center;
      transition: border-color 0.15s, background 0.15s;
    }
    .flavor-choice-btn:hover {
      border-color: var(--accent);
      background: rgba(56, 189, 248, 0.1);
    }
    .flavor-choice-btn strong {
      display: block;
      font-size: 0.92rem;
      color: var(--accent);
      margin-bottom: 0.25rem;
    }
    .flavor-choice-btn span {
      font-size: 0.78rem;
      color: var(--muted);
    }
    .compose-header-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.65rem;
      font-size: 0.85rem;
    }
    .compose-flavor-label {
      font-weight: 600;
      color: var(--accent);
    }
    .compose-input-text {
      width: 100%;
      background: #0b0f19;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      padding: 0.55rem 0.75rem;
      font-family: inherit;
      font-size: 0.95rem;
      margin-bottom: 0.75rem;
    }
    .compose-input-text:focus { outline: none; border-color: var(--accent); }
    .gallery-upload-row {
      background: #0b0f19;
      border: 1px dashed var(--border);
      border-radius: 6px;
      padding: 0.65rem 0.75rem;
      margin-bottom: 0.75rem;
      font-size: 0.85rem;
      color: var(--muted);
    }
    .gallery-upload-row input[type="file"] {
      display: block;
      margin-top: 0.35rem;
      color: var(--text);
      font-size: 0.82rem;
    }
    .dashboard-title {
      font-size: 1rem;
      font-weight: 600;
      color: var(--accent);
      margin-bottom: 0.75rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .dashboard-form {
      display: grid;
      grid-template-columns: 1fr 1fr 1fr auto;
      gap: 0.5rem;
      margin-bottom: 1rem;
      align-items: center;
    }
    @media (max-width: 600px) {
      .dashboard-form { grid-template-columns: 1fr; }
    }
    .dashboard-form input {
      background: #0b0f19;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      padding: 0.45rem 0.65rem;
      font-size: 0.85rem;
    }
    .dashboard-form input:focus { outline: none; border-color: var(--accent); }
    .user-list {
      border-top: 1px solid var(--border);
      padding-top: 0.75rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    .user-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.85rem;
      padding: 0.4rem 0.6rem;
      background: #0b0f19;
      border: 1px solid var(--border);
      border-radius: 6px;
    }
    .editor-tabs, .filter-tabs {
      display: flex;
      gap: 0.4rem;
      margin-bottom: 0.75rem;
      flex-wrap: wrap;
    }
    .editor-tab, .filter-tab {
      background: #0b0f19;
      color: var(--muted);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.3rem 0.7rem;
      font-size: 0.8rem;
      font-weight: 600;
      cursor: pointer;
    }
    .editor-tab.active, .filter-tab.active {
      background: rgba(56, 189, 248, 0.15);
      color: var(--accent);
      border-color: var(--accent);
    }
    .compose-box textarea {
      width: 100%;
      background: #0b0f19;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      padding: 0.75rem;
      font-family: inherit;
      font-size: 0.95rem;
      resize: vertical;
    }
    .compose-box textarea.markdown-mode {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.9rem;
    }
    .compose-box textarea:focus { outline: none; border-color: var(--accent); }
    #quill-wrapper {
      background: #0b0f19;
      border-radius: 6px;
      color: var(--text);
    }
    #quill-wrapper .ql-toolbar.ql-snow {
      border-color: var(--border);
      background: #101726;
      border-top-left-radius: 6px;
      border-top-right-radius: 6px;
    }
    #quill-wrapper .ql-container.ql-snow {
      border-color: var(--border);
      border-bottom-left-radius: 6px;
      border-bottom-right-radius: 6px;
      font-family: inherit;
      font-size: 0.95rem;
      min-height: 110px;
    }
    #quill-wrapper .ql-editor {
      min-height: 110px;
      color: var(--text);
    }
    #quill-wrapper .ql-editor.ql-blank::before {
      color: var(--muted);
      font-style: normal;
    }
    #quill-wrapper .ql-snow .ql-stroke { stroke: var(--muted); }
    #quill-wrapper .ql-snow .ql-fill { fill: var(--muted); }
    #quill-wrapper .ql-snow .ql-picker { color: var(--muted); }
    #quill-wrapper .ql-snow .ql-picker-options { background: var(--card-bg); border-color: var(--border); }
    .compose-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 0.75rem;
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    .compose-checks {
      display: flex;
      align-items: center;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .checkbox-label {
      font-size: 0.85rem;
      color: var(--muted);
      display: flex;
      align-items: center;
      gap: 0.4rem;
      cursor: pointer;
    }
    .starred-header {
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--star-color);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 0.6rem;
    }
    .starred-list {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    .starred-link {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      background: #0b0f19;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.35rem 0.65rem;
      color: var(--text);
      text-decoration: none;
      font-size: 0.85rem;
      transition: border-color 0.15s;
    }
    .starred-link:hover { border-color: var(--star-color); color: var(--accent); }
    .feed-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    .feed-title { font-size: 1rem; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
    .feed-count { font-size: 0.8rem; color: var(--muted); }
    .message-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      margin-bottom: 0.9rem;
    }
    .message-meta {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.8rem;
      color: var(--muted);
      margin-bottom: 0.5rem;
    }
    .message-meta-right {
      display: flex;
      align-items: center;
      gap: 0.45rem;
    }
    .message-title {
      font-size: 1.15rem;
      font-weight: 700;
      color: var(--accent);
      margin-bottom: 0.5rem;
    }
    .gallery-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 0.6rem;
      margin-bottom: 0.65rem;
    }
    .gallery-grid img {
      width: 100%;
      max-height: 260px;
      object-fit: cover;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: #0b0f19;
    }
    .author { font-weight: 600; color: var(--text); }
    .badge {
      display: inline-block;
      padding: 0;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .badge-public { color: var(--public-color); }
    .badge-private { color: var(--private-color); }
    .badge-crypto { color: var(--crypto-color); }
    .badge-superuser { color: var(--accent); }
    .badge-disabled { color: var(--danger-color); }
    .badge-format { color: var(--muted); }
    .badge-flavor { color: var(--accent); }
    .badge-star { color: var(--star-color); }
    .message-content {
      font-size: 0.95rem;
      word-break: break-word;
    }
    .message-content .plain-text {
      white-space: pre-wrap;
    }
    .message-content .rich-content p { margin-bottom: 0.5rem; }
    .message-content .rich-content p:last-child { margin-bottom: 0; }
    .message-content .rich-content h1,
    .message-content .rich-content h2,
    .message-content .rich-content h3 {
      margin: 0.6rem 0 0.35rem;
      color: var(--accent);
      line-height: 1.3;
    }
    .message-content .rich-content ul,
    .message-content .rich-content ol {
      margin: 0.4rem 0 0.6rem 1.5rem;
    }
    .message-content .rich-content blockquote {
      border-left: 3px solid var(--accent);
      padding-left: 0.75rem;
      color: var(--muted);
      margin: 0.5rem 0;
    }
    .message-content .rich-content pre {
      background: #0b0f19;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.65rem;
      overflow-x: auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      margin: 0.5rem 0;
    }
    .message-content .rich-content code {
      background: #0b0f19;
      padding: 0.12rem 0.3rem;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
    }
    .message-content .rich-content pre code {
      background: transparent;
      padding: 0;
    }
    .message-content .rich-content a {
      color: var(--accent);
      text-decoration: underline;
    }
    .message-content .rich-content img,
    #quill-wrapper .ql-editor img {
      max-width: 100%;
      height: auto;
      border-radius: 6px;
      margin: 0.4rem 0;
    }
    .stardate-tag { font-family: monospace; }
    .permalink {
      color: var(--muted);
      text-decoration: none;
    }
    .permalink:hover {
      color: var(--accent);
      text-decoration: underline;
    }
    .more-link-row {
      margin-top: 0.5rem;
    }
    .more-link {
      display: inline-block;
      font-size: 0.8rem;
      font-weight: 700;
      color: var(--accent);
      text-decoration: none;
      letter-spacing: 0.5px;
    }
    .more-link:hover {
      text-decoration: underline;
    }
    .empty-state {
      text-align: center;
      padding: 3rem 1rem;
      color: var(--muted);
      border: 1px dashed var(--border);
      border-radius: 8px;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <h1>{{.SiteTitle}}</h1>
        {{if and (not .HideStardates) (not .SinglePost)}}<div class="stardate-live">Stardate {{.CurrentStardate}}</div>{{end}}
      </div>
      <div class="nav-actions">
        {{if .SinglePost}}
          <a href="{{.BasePath}}/" class="btn btn-primary">&larr; Recent Posts</a>
        {{else}}
          {{if .LoggedIn}}
            <span class="user-tag">
              User: <strong>{{.User}}</strong>
              {{if .IsCrypto}}<span class="badge badge-crypto" title="Encrypted Crypto Identity">Crypto</span>{{end}}
              {{if .IsSuperuser}}<span class="badge badge-superuser" title="Superuser">Superuser</span>{{end}}
            </span>
            <button id="compose-btn" class="btn btn-primary" onclick="showCompose()">New Post</button>
            <a href="{{.BasePath}}/logout" class="btn btn-muted" onclick="return doLogout(event)">Logout</a>
            {{if .IsSuperuser}}
              <details class="dropdown-menu">
                <summary class="dropdown-trigger" title="Superuser Menu">&#9660;</summary>
                <div class="dropdown-list">
                  <button type="button" id="dashboard-btn" class="dropdown-item" onclick="toggleDashboard()">User Dashboard</button>
                </div>
              </details>
            {{end}}
          {{else}}
            <a href="{{.BasePath}}/login" class="btn btn-primary">LOGIN</a>
          {{end}}
        {{end}}
      </div>
    </header>

    {{if and .IsSuperuser (not .SinglePost)}}
    <div id="dashboard-section" class="dashboard-box" style="display: {{if .ShowDashboard}}block{{else}}none{{end}};">
      <div class="dashboard-title">
        <span>User Dashboard (pwfile)</span>
        <button type="button" class="btn btn-muted" onclick="toggleDashboard()">Close</button>
      </div>
      <form class="dashboard-form" method="POST" action="{{.BasePath}}/users">
        <input type="text" name="handle" placeholder="Handle (a-z0-9_)" pattern="[a-zA-Z0-9_]+" required>
        <input type="text" name="display" placeholder="Display Name (optional)">
        <input type="text" name="pw" placeholder="Plaintext Password" required>
        <button type="submit" class="btn btn-primary">Add User</button>
      </form>
      <div class="user-list">
        {{if .PWUsers}}
          {{range .PWUsers}}
          <div class="user-row">
            <div>
              <strong>@{{.Handle}}</strong>
              {{if .Display}}<span style="color: var(--muted);">({{.Display}})</span>{{end}}
              {{if .Superuser}}<span class="badge badge-superuser">Superuser</span>{{end}}
              {{if .Disabled}}
                <span class="badge badge-disabled">Disabled</span>
              {{else}}
                <span class="badge badge-public">Active</span>
              {{end}}
            </div>
            <div>
              <form style="display: inline;" method="POST" action="{{$.BasePath}}/users/disable">
                <input type="hidden" name="handle" value="{{.Handle}}">
                {{if .Disabled}}
                  <input type="hidden" name="disabled" value="0">
                  <button type="submit" class="btn-edit">Enable</button>
                {{else}}
                  <input type="hidden" name="disabled" value="1">
                  <button type="submit" class="btn-hide">Disable</button>
                {{end}}
              </form>
            </div>
          </div>
          {{end}}
        {{else}}
          <div style="color: var(--muted); font-size: 0.85rem;">No users in pwfile.</div>
        {{end}}
      </div>
    </div>
    {{end}}

    {{if .LoggedIn}}
    <div id="compose-section" class="compose-box" style="display: none;">
      <div id="flavor-chooser">
        <div class="flavor-chooser-title">Choose what you are creating:</div>
        <div class="flavor-options">
          <button type="button" class="flavor-choice-btn" onclick="chooseFlavor('log')">
            <strong>Log Post</strong>
            <span>Quick microblog or note</span>
          </button>
          <button type="button" class="flavor-choice-btn" onclick="chooseFlavor('article')">
            <strong>Article Page</strong>
            <span>Titled article, may be starred</span>
          </button>
          <button type="button" class="flavor-choice-btn" onclick="chooseFlavor('gallery')">
            <strong>Image Gallery</strong>
            <span>Photos &amp; captions, may be starred</span>
          </button>
        </div>
        <div style="text-align: right;">
          <button type="button" class="btn btn-muted" onclick="hideCompose()">Cancel</button>
        </div>
      </div>

      <form id="compose-form" style="display: none;" method="POST" action="{{.BasePath}}/post" enctype="multipart/form-data" onsubmit="return prepareSubmit(event)">
        <input type="hidden" id="edit-id-input" name="edit_id" value="">
        <input type="hidden" id="flavor-input" name="flavor" value="log">
        <input type="hidden" id="format-input" name="format" value="html">
        <input type="hidden" id="existing-images-input" name="existing_images" value="">
        <input type="hidden" id="existing-attachments-input" name="existing_attachments" value="">
        <div class="compose-header-row">
          <div>
            <span id="compose-flavor-label" class="compose-flavor-label">Creating: Log Post</span>
            <span id="edit-banner" style="display: none; color: var(--accent); margin-left: 0.5rem; font-weight: 600;">
              (Editing #<span id="edit-id-display"></span>)
            </span>
          </div>
          <button type="button" id="change-flavor-btn" class="btn btn-muted" style="padding: 0.15rem 0.5rem; font-size: 0.78rem;" onclick="showFlavorChooser()">Change Type</button>
        </div>
        <div id="title-row" style="display: none;">
          <input type="text" id="title-input" name="title" class="compose-input-text" placeholder="Title">
        </div>
        <div id="gallery-row" class="gallery-upload-row" style="display: none;">
          <label for="images-input">Upload Gallery Images:</label>
          <input type="file" id="images-input" name="images" accept="image/*" multiple>
          <div id="existing-images-note" style="display: none; margin-top: 0.35rem; font-size: 0.78rem; color: var(--accent);"></div>
        </div>
        <div id="attachments-row" class="gallery-upload-row">
          <label for="attachments-input">Upload Attachments (optional):</label>
          <input type="file" id="attachments-input" name="attachments" multiple>
          <div id="existing-attachments-note" style="display: none; margin-top: 0.35rem; font-size: 0.78rem; color: var(--accent);"></div>
        </div>
        <div class="editor-tabs">
          <button type="button" id="tab-html" class="editor-tab active" onclick="setEditorMode('html')">Rich Text (Quill)</button>
          <button type="button" id="tab-markdown" class="editor-tab" onclick="setEditorMode('markdown')">Markdown</button>
          <button type="button" id="tab-text" class="editor-tab" onclick="setEditorMode('text')">Plain Text</button>
        </div>
        <textarea id="content-input" name="content" rows="4" style="display: none;" placeholder="{{if .IsCrypto}}Write a public post or end-to-end encrypted private note...{{else}}Write a public post or private note...{{end}}"></textarea>
        <div id="quill-wrapper" style="display: block;">
          <div id="quill-editor"></div>
        </div>
        <div class="compose-footer">
          <div class="compose-checks">
            <label class="checkbox-label">
              <input type="checkbox" id="public1-input" name="public1" value="1">
              <input type="checkbox" id="public2-input" name="public2" value="1">
              <span>public note (check both)</span>
            </label>
            <label id="starred-check-wrapper" class="checkbox-label" style="display: none;">
              <input type="checkbox" id="starred-input" name="is_starred" value="1">
              <span style="color: var(--star-color);">&#9733; Starred</span>
            </label>
          </div>
          <div>
            <button type="button" class="btn btn-muted" onclick="hideCompose()">Cancel</button>
            <button type="submit" id="submit-btn" class="btn btn-primary">Publish</button>
          </div>
        </div>
      </form>
    </div>
    {{end}}

    <div id="feed-section">
    {{if not .SinglePost}}
    {{if .StarredItems}}
    <div class="starred-box">
      <div class="starred-header">&#9733; Starred Articles &amp; Galleries</div>
      <div class="starred-list">
        {{range .StarredItems}}
          <a href="{{$.BasePath}}/{{.ID}}" class="starred-link">
            <span class="badge badge-star">&#9733;</span>
            <span class="badge badge-flavor">{{if eq .Flavor "gallery"}}Gallery{{else}}Article{{end}}</span>
            <strong>{{if .Title}}{{.Title}}{{else}}#{{.ID}}{{end}}</strong>
          </a>
        {{end}}
      </div>
    </div>
    {{end}}

    <div class="feed-header">
      <div class="feed-title">Recent Posts</div>
      <div class="filter-tabs">
        <button type="button" class="filter-tab active" data-filter="all" onclick="filterFeed('all')">All</button>
        <button type="button" class="filter-tab" data-filter="log" onclick="filterFeed('log')">Logs</button>
        <button type="button" class="filter-tab" data-filter="article" onclick="filterFeed('article')">Articles</button>
        <button type="button" class="filter-tab" data-filter="gallery" onclick="filterFeed('gallery')">Galleries</button>
      </div>
      <div class="feed-count">{{len .Messages}} entries (max 100)</div>
    </div>
    {{end}}

    <div class="feed">
      {{if .Messages}}
        {{range $m := .Messages}}
        <div id="post-{{$m.ID}}" class="message-card" data-flavor="{{$m.Flavor}}">
          <div class="message-meta">
            <div>
              <span class="author">@{{$m.Author}}</span>
              {{if not $.HideStardates}}
                &middot;
                <span class="stardate-tag">Stardate {{$m.Stardate}}</span>
              {{end}}
              &middot;
              <a href="{{$.BasePath}}/{{$m.ID}}" class="permalink">{{$m.UTC}}</a>
            </div>
            <div class="message-meta-right">
              {{if $m.IsStarred}}<span class="badge badge-star" title="Starred">&#9733; Starred</span>{{end}}
              {{if eq $m.Flavor "article"}}<span class="badge badge-flavor">Article</span>{{end}}
              {{if eq $m.Flavor "gallery"}}<span class="badge badge-flavor">Gallery</span>{{end}}
              {{if eq $m.Format "markdown"}}<span class="badge badge-format">MD</span>{{end}}
              {{if eq $m.Format "html"}}<span class="badge badge-format">Rich</span>{{end}}
              {{if $m.IsPublic}}
                <span class="badge badge-public">Public</span>
              {{else}}
                <span class="badge badge-private">Private</span>
              {{end}}
              {{if or $m.CanEdit $m.CanHide}}
                <details class="dropdown-menu">
                  <summary class="dropdown-trigger" title="Actions">&#9660;</summary>
                  <div class="dropdown-list">
                    {{if $m.CanEdit}}
                      <button type="button" class="dropdown-item"
                        data-id="{{$m.ID}}"
                        data-flavor="{{$m.Flavor}}"
                        data-title="{{$m.Title}}"
                        data-images="{{$m.ImagesCSV}}"
                        data-attachments="{{$m.AttachmentsCSV}}"
                        data-starred="{{if $m.IsStarred}}1{{else}}0{{end}}"
                        data-format="{{$m.Format}}"
                        data-public="{{if $m.IsPublic}}1{{else}}0{{end}}"
                        data-has-more="{{if $m.HasMore}}1{{else}}0{{end}}"
                        data-content="{{$m.Content}}"
                        onclick="startEdit(this)">EDIT</button>
                    {{end}}
                    {{if $m.CanHide}}
                      <form class="inline-form" method="POST" action="{{$.BasePath}}/hide">
                        <input type="hidden" name="id" value="{{$m.ID}}">
                        <button type="submit" class="dropdown-item dropdown-item-danger">HIDE</button>
                      </form>
                    {{end}}
                  </div>
                </details>
              {{end}}
            </div>
          </div>
          {{if $m.Title}}<div class="message-title">{{$m.Title}}</div>{{end}}
          {{if $m.Images}}
            <div class="gallery-grid">
              {{range $m.Images}}
                <a href="{{$.BasePath}}/images/{{$m.ID}}/{{.}}" target="_blank" rel="noopener">
                  <img src="{{$.BasePath}}/images/{{$m.ID}}/{{.}}" alt="{{.}}">
                </a>
              {{end}}
            </div>
          {{end}}
          <div class="message-content">
            {{if $.SinglePost}}
              {{$m.RenderedHTML}}
            {{else}}
              {{$m.SummaryHTML}}
              {{if $m.HasMore}}
                <div class="more-link-row"><a href="{{$.BasePath}}/{{$m.ID}}" class="more-link">MORE</a></div>
              {{end}}
            {{end}}
          </div>
          {{if $m.Attachments}}
            <div class="attachments-list" style="margin-top: 0.75rem; font-size: 0.85rem;">
              {{range $m.Attachments}}
                <a href="{{$.BasePath}}/attachments/{{$m.ID}}/{{.}}" target="_blank" rel="noopener" style="margin-right: 0.75rem; color: var(--accent);">&#128206; {{.}}</a>
              {{end}}
            </div>
          {{end}}
        </div>
        {{end}}
      {{else}}
        <div class="empty-state">
          <p>No messages yet.</p>
          {{if not .LoggedIn}}<p style="margin-top: 0.5rem;">Click LOGIN above to post.</p>{{end}}
        </div>
      {{end}}
    </div>
    </div>
  </div>

  {{if .LoggedIn}}<script src="/static/quill.js"></script>{{end}}
  <script>
    var quillInstance = null;
    var currentMode = 'html';
    var currentFlavor = 'log';

    function closeAllDropdowns(exceptEl) {
      var menus = document.querySelectorAll('details.dropdown-menu[open]');
      for (var i = 0; i < menus.length; i++) {
        if (menus[i] !== exceptEl) {
          menus[i].removeAttribute('open');
        }
      }
    }

    document.addEventListener('click', function(e) {
      var clickedMenu = e.target.closest ? e.target.closest('details.dropdown-menu') : null;
      closeAllDropdowns(clickedMenu);
    });

    function toggleDashboard() {
      closeAllDropdowns(null);
      var el = document.getElementById('dashboard-section');
      if (!el) return;
      el.style.display = (el.style.display === 'none' || el.style.display === '') ? 'block' : 'none';
    }

    function filterFeed(flavor) {
      var tabs = document.querySelectorAll('.filter-tab');
      for (var i = 0; i < tabs.length; i++) {
        tabs[i].classList.toggle('active', tabs[i].getAttribute('data-filter') === flavor);
      }
      var cards = document.querySelectorAll('.message-card');
      for (var j = 0; j < cards.length; j++) {
        var cardFlavor = cards[j].getAttribute('data-flavor') || 'log';
        if (flavor === 'all' || cardFlavor === flavor) {
          cards[j].style.display = '';
        } else {
          cards[j].style.display = 'none';
        }
      }
    }

    function initQuillIfNeeded() {
      if (quillInstance || typeof Quill === 'undefined') return;
      try {
        var ImageBlot = Quill.import('formats/image');
        if (ImageBlot) {
          ImageBlot.sanitize = function(url) { return url; };
        }
      } catch (err) {}
      quillInstance = new Quill('#quill-editor', {
        theme: 'snow',
        placeholder: 'Write formatted rich text...',
        modules: {
          uploader: {
            mimetypes: ['image/png', 'image/jpeg', 'image/gif', 'image/webp']
          },
          toolbar: [
            [{ 'header': [1, 2, 3, false] }],
            ['bold', 'italic', 'underline', 'strike'],
            ['blockquote', 'code-block'],
            [{ 'list': 'ordered'}, { 'list': 'bullet' }],
            ['link', 'image', 'clean']
          ]
        }
      });
    }

    function applyFlavorUI(flavor) {
      currentFlavor = flavor || 'log';
      document.getElementById('flavor-input').value = currentFlavor;
      var labelMap = {
        'log': 'Creating: Log Post',
        'article': 'Creating: Article Page',
        'gallery': 'Creating: Image Gallery'
      };
      document.getElementById('compose-flavor-label').textContent = labelMap[currentFlavor] || 'Creating: Log Post';
      var isArticleOrGallery = (currentFlavor === 'article' || currentFlavor === 'gallery');
      document.getElementById('title-row').style.display = isArticleOrGallery ? 'block' : 'none';
      document.getElementById('starred-check-wrapper').style.display = isArticleOrGallery ? 'flex' : 'none';
      document.getElementById('gallery-row').style.display = (currentFlavor === 'gallery') ? 'block' : 'none';
      document.getElementById('attachments-row').style.display = (currentFlavor === 'gallery') ? 'none' : 'block';
      if (currentFlavor === 'gallery') {
        var attInput = document.getElementById('attachments-input');
        if (attInput) attInput.value = '';
        document.getElementById('existing-attachments-input').value = '';
        document.getElementById('existing-attachments-note').style.display = 'none';
      }
      if (!isArticleOrGallery) {
        document.getElementById('starred-input').checked = false;
      }
    }

    function showFlavorChooser() {
      var feedEl = document.getElementById('feed-section');
      if (feedEl) feedEl.style.display = 'none';
      document.getElementById('flavor-chooser').style.display = 'block';
      document.getElementById('compose-form').style.display = 'none';
    }

    function chooseFlavor(flavor) {
      var feedEl = document.getElementById('feed-section');
      if (feedEl) feedEl.style.display = 'none';
      applyFlavorUI(flavor);
      document.getElementById('flavor-chooser').style.display = 'none';
      document.getElementById('compose-form').style.display = 'block';
      if (currentMode === 'html') {
        initQuillIfNeeded();
      }
      if (flavor === 'article' || flavor === 'gallery') {
        document.getElementById('title-input').focus();
      } else if (currentMode === 'html' && quillInstance) {
        quillInstance.focus();
      } else {
        document.getElementById('content-input').focus();
      }
    }

    function setEditorMode(mode) {
      currentMode = mode;
      document.getElementById('format-input').value = mode;
      document.getElementById('tab-text').classList.toggle('active', mode === 'text');
      document.getElementById('tab-markdown').classList.toggle('active', mode === 'markdown');
      document.getElementById('tab-html').classList.toggle('active', mode === 'html');

      var ta = document.getElementById('content-input');
      var qw = document.getElementById('quill-wrapper');

      if (mode === 'html') {
        initQuillIfNeeded();
        ta.style.display = 'none';
        qw.style.display = 'block';
        if (quillInstance) quillInstance.focus();
      } else {
        qw.style.display = 'none';
        ta.style.display = 'block';
        ta.classList.toggle('markdown-mode', mode === 'markdown');
        ta.focus();
      }
    }

    function prepareSubmit(e) {
      if (currentMode === 'html' && quillInstance) {
        var text = quillInstance.getText().trim();
        var hasImg = quillInstance.root.querySelector('img') !== null;
        if (!text && !hasImg && currentFlavor === 'log') {
          if (e) e.preventDefault();
          return false;
        }
        var html = (text || hasImg) ? (quillInstance.getSemanticHTML ? quillInstance.getSemanticHTML() : quillInstance.root.innerHTML) : '';
        document.getElementById('content-input').value = html;
      }
      return true;
    }

    function showCompose() {
      document.getElementById('edit-id-input').value = '';
      document.getElementById('edit-banner').style.display = 'none';
      document.getElementById('submit-btn').textContent = 'Publish';
      document.getElementById('title-input').value = '';
      document.getElementById('content-input').value = '';
      document.getElementById('existing-images-input').value = '';
      document.getElementById('existing-images-note').style.display = 'none';
      document.getElementById('existing-attachments-input').value = '';
      document.getElementById('existing-attachments-note').style.display = 'none';
      var imgInput = document.getElementById('images-input');
      if (imgInput) imgInput.value = '';
      var attInput = document.getElementById('attachments-input');
      if (attInput) attInput.value = '';
      document.getElementById('public1-input').checked = false;
      document.getElementById('public2-input').checked = false;
      document.getElementById('starred-input').checked = false;
      setEditorMode('html');
      if (quillInstance) {
        quillInstance.setText('');
      }
      document.getElementById('compose-section').style.display = 'block';
      var composeBtn = document.getElementById('compose-btn');
      if (composeBtn) composeBtn.style.display = 'none';
      var feedEl = document.getElementById('feed-section');
      if (feedEl) feedEl.style.display = 'none';
      showFlavorChooser();
    }

    function applyEditorContent(fmt, content) {
      document.getElementById('content-input').value = content;
      if (fmt === 'html') {
        initQuillIfNeeded();
        if (quillInstance) {
          quillInstance.setText('');
          if (content) {
            quillInstance.clipboard.dangerouslyPasteHTML(content);
          }
          quillInstance.focus();
        }
      } else if (quillInstance) {
        quillInstance.setText('');
      }
    }

    function startEdit(btn) {
      closeAllDropdowns(null);
      var id = btn.getAttribute('data-id') || '';
      var flavor = btn.getAttribute('data-flavor') || 'log';
      var title = btn.getAttribute('data-title') || '';
      var imagesCSV = btn.getAttribute('data-images') || '';
      var attachmentsCSV = btn.getAttribute('data-attachments') || '';
      var isStarred = btn.getAttribute('data-starred') === '1';
      var fmt = btn.getAttribute('data-format') || 'text';
      var isPub = btn.getAttribute('data-public') === '1';
      var hasMore = btn.getAttribute('data-has-more') === '1';
      var content = btn.getAttribute('data-content') || '';

      document.getElementById('edit-id-input').value = id;
      document.getElementById('edit-id-display').textContent = id;
      document.getElementById('edit-banner').style.display = 'inline';
      document.getElementById('submit-btn').textContent = 'Save Changes';
      document.getElementById('title-input').value = title;
      document.getElementById('existing-images-input').value = imagesCSV;
      var noteEl = document.getElementById('existing-images-note');
      if (imagesCSV) {
        noteEl.textContent = 'Existing images: ' + imagesCSV;
        noteEl.style.display = 'block';
      } else {
        noteEl.style.display = 'none';
      }
      document.getElementById('existing-attachments-input').value = attachmentsCSV;
      var attNoteEl = document.getElementById('existing-attachments-note');
      if (attachmentsCSV) {
        attNoteEl.textContent = 'Existing attachments: ' + attachmentsCSV;
        attNoteEl.style.display = 'block';
      } else {
        attNoteEl.style.display = 'none';
      }
      document.getElementById('public1-input').checked = isPub;
      document.getElementById('public2-input').checked = isPub;
      document.getElementById('starred-input').checked = isStarred;

      document.getElementById('compose-section').style.display = 'block';
      var composeBtn = document.getElementById('compose-btn');
      if (composeBtn) composeBtn.style.display = 'none';
      var feedEl = document.getElementById('feed-section');
      if (feedEl) feedEl.style.display = 'none';
      chooseFlavor(flavor);

      setEditorMode(fmt);
      applyEditorContent(fmt, content);
      if (hasMore && id) {
        fetch("{{.BasePath}}/" + id + "?format=json", { credentials: "same-origin" })
          .then(function(r) { return r.ok ? r.json() : null; })
          .then(function(post) {
            if (post && typeof post.content === "string") {
              applyEditorContent(fmt, post.content);
            }
          });
      }
      document.getElementById('compose-section').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function hideCompose() {
      document.getElementById('edit-id-input').value = '';
      document.getElementById('edit-banner').style.display = 'none';
      document.getElementById('compose-section').style.display = 'none';
      var composeBtn = document.getElementById('compose-btn');
      if (composeBtn) composeBtn.style.display = 'inline-block';
      var feedEl = document.getElementById('feed-section');
      if (feedEl) feedEl.style.display = 'block';
    }
    function doLogout(e) {
      if (e) e.preventDefault();
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "{{.BasePath}}/logout", true, "logout", "logout");
      xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
      xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
          window.location.href = "{{.BasePath}}/";
        }
      };
      xhr.send();
      return false;
    }
  </script>
</body>
</html>
`


