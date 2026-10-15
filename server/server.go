package server

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds configuration parameters for the stardate server.
type Config struct {
	Addr         string        // HTTPS TCP address to listen on, e.g. ":8443"
	HTTPSAddr    string        // HTTPS TCP address to listen on (alias for Addr)
	HTTPAddr     string        // Optional HTTP TCP address for testing, e.g. "localhost:8080"
	Password     string        // Shared password for Basic authentication
	PWFile       string        // Path to JSONL password file (optional)
	Salt         string        // Salt for deriving crypto username and password hashes
	DataFile     string        // Path to JSON persistence file (optional)
	CertFile     string        // Path to TLS certificate (optional)
	KeyFile      string        // Path to TLS private key (optional)
	Hosts        []string      // Hostnames/IPs to include in generated certificate
	ReadTimeout  time.Duration // Maximum duration for reading the entire request
	WriteTimeout time.Duration // Maximum duration before timing out writes of the response
	IdleTimeout  time.Duration // Maximum amount of time to wait for the next request when keep-alives are enabled
}

// PWFileEntry represents a user record in the --pwfile JSONL file.
type PWFileEntry struct {
	Handle  string `json:"handle"`
	Display string `json:"display"`
	PW      string `json:"pw"`
	PWHash  string `json:"pwhash"`
}

// DefaultConfig returns default configuration values.
func DefaultConfig() Config {
	return Config{
		Addr:         ":8443",
		HTTPSAddr:    ":8443",
		Hosts:        []string{"localhost", "127.0.0.1", "::1"},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// StardateResponse represents the JSON payload returned for stardate queries.
type StardateResponse struct {
	User      string    `json:"user,omitempty"`
	IsCrypto  bool      `json:"is_crypto,omitempty"`
	Stardate  float64   `json:"stardate"`
	Formatted string    `json:"formatted"`
	UTC       string    `json:"utc"`
	Timestamp int64     `json:"timestamp"`
	Messages  []Message `json:"messages,omitempty"`
}

// AuthUser represents an authenticated user session.
type AuthUser struct {
	Username       string // Original or normalized handle supplied in credentials
	CryptoUsername string // First 10 hex digits of sha256(salt + username + password) if crypto user
	EffectiveUser  string // CryptoUsername if IsCrypto, else Display (or Username)
	CryptoKey      []byte // 32-byte sha256 key if IsCrypto, else nil
	IsCrypto       bool   // True if password has "/" + >= 12 ASCII characters beyond base password
}

// Server is the stardate HTTPS (and optional HTTP) server.
type Server struct {
	cfg             Config
	pwUsers         map[string]PWFileEntry
	store           *Store
	tmpl            *template.Template
	httpServer      *http.Server // HTTPS server
	httpPlainServer *http.Server // Optional HTTP server for testing
	listener        net.Listener // HTTPS listener
	httpListener    net.Listener // HTTP listener
}

// isValidHandle checks that h is non-empty and consists only of ASCII [a-zA-Z0-9_].
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

// New creates and initializes a new stardate Server.
func New(cfg Config) (*Server, error) {
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

	var pwUsers map[string]PWFileEntry
	if cfg.PWFile != "" {
		var err error
		pwUsers, err = loadPWFile(cfg.PWFile)
		if err != nil {
			return nil, err
		}
	}

	st, err := NewStore(cfg.DataFile)
	if err != nil {
		return nil, fmt.Errorf("store initialization failed: %w", err)
	}

	tmpl, err := template.New("index").Parse(indexHTML)
	if err != nil {
		return nil, fmt.Errorf("template parsing failed: %w", err)
	}

	mux := http.NewServeMux()
	s := &Server{
		cfg:     cfg,
		pwUsers: pwUsers,
		store:   st,
		tmpl:    tmpl,
	}

	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/post", s.handlePost)
	mux.HandleFunc("/stardate", s.handleStardate)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/static/quill.js", s.handleStaticQuillJS)
	mux.HandleFunc("/static/quill.snow.css", s.handleStaticQuillCSS)

	if cfg.Addr != "" {
		tlsCert, err := LoadOrGenerateCert(cfg.CertFile, cfg.KeyFile, cfg.Hosts)
		if err != nil {
			return nil, fmt.Errorf("certificate setup failed: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		}

		s.httpServer = &http.Server{
			Addr:         cfg.Addr,
			Handler:      mux,
			TLSConfig:    tlsConfig,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		}
	}

	if cfg.HTTPAddr != "" {
		s.httpPlainServer = &http.Server{
			Addr:         cfg.HTTPAddr,
			Handler:      mux,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		}
	}

	return s, nil
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

// Store returns the message store.
func (s *Server) Store() *Store {
	return s.store
}

// authenticate verifies HTTP Basic Authentication credentials.
// If the user has explicitly logged out, it treats them as unauthenticated.
func (s *Server) authenticate(r *http.Request) (*AuthUser, bool) {
	if c, err := r.Cookie("stardate_logout"); err == nil && c.Value == "1" {
		return nil, false
	}
	return s.checkCredentials(r)
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

// checkCredentials validates HTTP Basic Auth credentials against --pwfile entries first,
// and falls back to the shared --pw password if --pw is non-empty.
// For crypto users, the password must be BasePassword + "/" + at least 12 ASCII characters,
// or else the credentials are rejected.
func (s *Server) checkCredentials(r *http.Request) (*AuthUser, bool) {
	user, pass, ok := r.BasicAuth()
	if !ok || strings.TrimSpace(user) == "" {
		return nil, false
	}
	user = strings.TrimSpace(user)

	// 1. Check --pwfile users if configured and handle is valid ASCII [a-z0-9_]+
	if len(s.pwUsers) > 0 && isValidHandle(user) {
		normHandle := strings.ToLower(user)
		if entry, exists := s.pwUsers[normHandle]; exists {
			extra, matched := matchPWEntry(s.cfg.Salt, entry, pass)
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
				}, true
			}
			if !isValidCryptoExtra(extra) {
				return nil, false
			}
			cryptoUser, key := DeriveCryptoIdentity(s.cfg.Salt, entry.Handle, pass)
			return &AuthUser{
				Username:       entry.Handle,
				CryptoUsername: cryptoUser,
				EffectiveUser:  cryptoUser,
				CryptoKey:      key,
				IsCrypto:       true,
			}, true
		}
	}

	// 2. Fallback to shared password (--pw) if non-empty
	if s.cfg.Password == "" {
		return nil, false
	}

	// Check only the first len(shared_pw) characters of the user's password
	pwLen := len(s.cfg.Password)
	if len(pass) < pwLen {
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(pass[:pwLen]), []byte(s.cfg.Password)) != 1 {
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

	cryptoUser, key := DeriveCryptoIdentity(s.cfg.Salt, user, pass)
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
	ID           int64
	Author       string
	Content      string
	RenderedHTML template.HTML
	Format       string
	IsPublic     bool
	CanEdit      bool
	Stardate     string
	UTC          string
}

type pageData struct {
	LoggedIn        bool
	User            string
	IsCrypto        bool
	CurrentStardate string
	CurrentUTC      string
	Messages        []pageMessage
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	auth, loggedIn := s.authenticate(r)
	var viewer string
	if loggedIn {
		viewer = auth.EffectiveUser
	}

	recentMsgs := s.store.GetRecent(viewer, 100)

	// Decrypt any private messages belonging to this crypto user
	displayMsgs := make([]Message, len(recentMsgs))
	for i, m := range recentMsgs {
		displayMsgs[i] = m
		if !m.IsPublic && loggedIn && auth.IsCrypto && m.Author == auth.EffectiveUser {
			if decrypted, err := DecryptMessage(m.Content, auth.CryptoKey); err == nil {
				displayMsgs[i].Content = decrypted
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
		if loggedIn {
			userStr = auth.EffectiveUser
			isCrypto = auth.IsCrypto
		}
		res := StardateResponse{
			User:      userStr,
			IsCrypto:  isCrypto,
			Stardate:  sd,
			Formatted: fmt.Sprintf("%.2f", sd),
			UTC:       now.Format(time.RFC3339),
			Timestamp: now.Unix(),
			Messages:  displayMsgs,
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(res)
		return
	}

	viewMsgs := make([]pageMessage, 0, len(displayMsgs))
	for _, m := range displayMsgs {
		fmtNorm := NormalizeFormat(m.Format)
		viewMsgs = append(viewMsgs, pageMessage{
			ID:           m.ID,
			Author:       m.Author,
			Content:      m.Content,
			RenderedHTML: RenderAndSanitize(m.Content, fmtNorm),
			Format:       fmtNorm,
			IsPublic:     m.IsPublic,
			CanEdit:      loggedIn && m.Author == auth.EffectiveUser,
			Stardate:     fmt.Sprintf("%.2f", m.Stardate),
			UTC:          m.CreatedAt.Format("2006-01-02 15:04:05 UTC"),
		})
	}

	userName := ""
	isCrypto := false
	if loggedIn {
		userName = auth.EffectiveUser
		isCrypto = auth.IsCrypto
	}

	data := pageData{
		LoggedIn:        loggedIn,
		User:            userName,
		IsCrypto:        isCrypto,
		CurrentStardate: fmt.Sprintf("%.2f", sd),
		CurrentUTC:      now.Format(time.RFC3339),
		Messages:        viewMsgs,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, data); err != nil {
		log.Printf("template render error: %v", err)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
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

	auth, loggedIn := s.checkCredentials(r)
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
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Set the logout cookie so subsequent requests are unauthenticated
	http.SetCookie(w, &http.Cookie{
		Name:     "stardate_logout",
		Value:    "1",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	// Reset the prompted cookie
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

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	auth, loggedIn := s.authenticate(r)
	if !loggedIn {
		w.Header().Set("WWW-Authenticate", `Basic realm="stardate"`)
		http.Error(w, "Login required to post", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	format := NormalizeFormat(r.FormValue("format"))
	content := strings.TrimSpace(r.FormValue("content"))
	if format == FormatHTML {
		content = strings.TrimSpace(htmlPolicy.Sanitize(content))
		if content == "<p><br></p>" || content == "<p></p>" {
			content = ""
		}
	}
	if content == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	isChecked := func(v string) bool {
		return v == "1" || v == "on" || v == "true"
	}
	isPublic := isChecked(r.FormValue("public1")) && isChecked(r.FormValue("public2"))

	contentToStore := content
	if !isPublic && auth.IsCrypto {
		encrypted, err := EncryptMessage(content, auth.CryptoKey)
		if err != nil {
			http.Error(w, "Failed to encrypt private message", http.StatusInternalServerError)
			return
		}
		contentToStore = encrypted
	}

	editIDStr := strings.TrimSpace(r.FormValue("edit_id"))
	if editIDStr != "" {
		editID, err := strconv.ParseInt(editIDStr, 10, 64)
		if err != nil || editID <= 0 {
			http.Error(w, "Invalid edit_id", http.StatusBadRequest)
			return
		}
		if _, err := s.store.Update(editID, auth.EffectiveUser, contentToStore, format, isPublic); err != nil {
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
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if _, err := s.store.AddWithFormat(auth.EffectiveUser, contentToStore, format, isPublic); err != nil {
		http.Error(w, "Failed to save message", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleStardate(w http.ResponseWriter, r *http.Request) {
	s.handleRoot(w, r)
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
  <title>Stardate Log</title>
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
    }
    .brand h1 { font-size: 1.4rem; color: var(--accent); letter-spacing: 0.5px; }
    .brand .stardate-live { font-size: 0.85rem; color: var(--muted); font-family: monospace; }
    .nav-actions { display: flex; align-items: center; gap: 0.75rem; }
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
      margin-right: 0.35rem;
    }
    .btn-edit:hover {
      background: rgba(56, 189, 248, 0.15);
    }
    .user-tag { font-size: 0.85rem; color: var(--muted); display: flex; align-items: center; gap: 0.4rem; }
    .user-tag strong { color: var(--accent); }
    .compose-box {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      margin-bottom: 1.5rem;
    }
    .editor-tabs {
      display: flex;
      gap: 0.4rem;
      margin-bottom: 0.75rem;
    }
    .editor-tab {
      background: #0b0f19;
      color: var(--muted);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.3rem 0.7rem;
      font-size: 0.8rem;
      font-weight: 600;
      cursor: pointer;
    }
    .editor-tab.active {
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
    }
    .checkbox-label {
      font-size: 0.85rem;
      color: var(--muted);
      display: flex;
      align-items: center;
      gap: 0.4rem;
      cursor: pointer;
    }
    .feed-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
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
    .author { font-weight: 600; color: var(--text); }
    .badge {
      display: inline-block;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .badge-public { background: rgba(16, 185, 129, 0.15); color: var(--public-color); border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-private { background: rgba(245, 158, 11, 0.15); color: var(--private-color); border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-crypto { background: rgba(168, 85, 247, 0.15); color: var(--crypto-color); border: 1px solid rgba(168, 85, 247, 0.3); }
    .badge-format { background: rgba(139, 155, 180, 0.12); color: var(--muted); border: 1px solid var(--border); margin-right: 0.3rem; }
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
    .stardate-tag { font-family: monospace; }
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
        <h1>Stardate</h1>
        <div class="stardate-live">Stardate {{.CurrentStardate}}</div>
      </div>
      <div class="nav-actions">
        {{if .LoggedIn}}
          <span class="user-tag">
            User: <strong>{{.User}}</strong>
            {{if .IsCrypto}}<span class="badge badge-crypto" title="Encrypted Crypto Identity">Crypto</span>{{end}}
          </span>
          <button id="compose-btn" class="btn btn-primary" onclick="showCompose()">New Note</button>
          <a href="/logout" class="btn btn-muted" onclick="return doLogout(event)">Logout</a>
        {{else}}
          <a href="/login" class="btn btn-primary">LOGIN</a>
        {{end}}
      </div>
    </header>

    {{if .LoggedIn}}
    <div id="compose-section" class="compose-box" style="display: none;">
      <form id="compose-form" method="POST" action="/post" onsubmit="return prepareSubmit(event)">
        <input type="hidden" id="edit-id-input" name="edit_id" value="">
        <input type="hidden" id="format-input" name="format" value="text">
        <div id="edit-banner" style="display: none; font-size: 0.85rem; color: var(--accent); margin-bottom: 0.5rem; font-weight: 600;">
          Editing Note #<span id="edit-id-display"></span>
        </div>
        <div class="editor-tabs">
          <button type="button" id="tab-text" class="editor-tab active" onclick="setEditorMode('text')">Plain Text</button>
          <button type="button" id="tab-markdown" class="editor-tab" onclick="setEditorMode('markdown')">Markdown</button>
          <button type="button" id="tab-html" class="editor-tab" onclick="setEditorMode('html')">Rich Text (Quill)</button>
        </div>
        <textarea id="content-input" name="content" rows="4" placeholder="{{if .IsCrypto}}Write a public log or end-to-end encrypted private note...{{else}}Write a public log entry or private note...{{end}}" required></textarea>
        <div id="quill-wrapper" style="display: none;">
          <div id="quill-editor"></div>
        </div>
        <div class="compose-footer">
          <div class="checkbox-label">
            <input type="checkbox" id="public1-input" name="public1" value="1">
            <input type="checkbox" id="public2-input" name="public2" value="1">
            <span>public note (check both)</span>
          </div>
          <div>
            <button type="button" class="btn btn-muted" onclick="hideCompose()">Cancel</button>
            <button type="submit" id="submit-btn" class="btn btn-primary">Publish</button>
          </div>
        </div>
      </form>
    </div>
    {{end}}

    <div class="feed-header">
      <div class="feed-title">Recent Logs</div>
      <div class="feed-count">{{len .Messages}} entries (max 100)</div>
    </div>

    <div class="feed">
      {{if .Messages}}
        {{range .Messages}}
        <div class="message-card">
          <div class="message-meta">
            <div>
              <span class="author">@{{.Author}}</span>
              &middot;
              <span class="stardate-tag">Stardate {{.Stardate}}</span>
              &middot;
              <span>{{.UTC}}</span>
            </div>
            <div>
              {{if .CanEdit}}
                <button type="button" class="btn-edit"
                  data-id="{{.ID}}"
                  data-format="{{.Format}}"
                  data-public="{{if .IsPublic}}1{{else}}0{{end}}"
                  data-content="{{.Content}}"
                  onclick="startEdit(this)">EDIT</button>
              {{end}}
              {{if eq .Format "markdown"}}<span class="badge badge-format">MD</span>{{end}}
              {{if eq .Format "html"}}<span class="badge badge-format">Rich</span>{{end}}
              {{if .IsPublic}}
                <span class="badge badge-public">Public</span>
              {{else}}
                <span class="badge badge-private">Private</span>
              {{end}}
            </div>
          </div>
          <div class="message-content">{{.RenderedHTML}}</div>
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

  {{if .LoggedIn}}<script src="/static/quill.js"></script>{{end}}
  <script>
    var quillInstance = null;
    var currentMode = 'text';

    function initQuillIfNeeded() {
      if (quillInstance || typeof Quill === 'undefined') return;
      quillInstance = new Quill('#quill-editor', {
        theme: 'snow',
        placeholder: 'Write formatted rich text...',
        modules: {
          toolbar: [
            [{ 'header': [1, 2, 3, false] }],
            ['bold', 'italic', 'underline', 'strike'],
            ['blockquote', 'code-block'],
            [{ 'list': 'ordered'}, { 'list': 'bullet' }],
            ['link', 'clean']
          ]
        }
      });
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
        ta.removeAttribute('required');
        qw.style.display = 'block';
        if (quillInstance) quillInstance.focus();
      } else {
        qw.style.display = 'none';
        ta.style.display = 'block';
        ta.setAttribute('required', 'required');
        ta.classList.toggle('markdown-mode', mode === 'markdown');
        ta.focus();
      }
    }

    function prepareSubmit(e) {
      if (currentMode === 'html' && quillInstance) {
        var text = quillInstance.getText().trim();
        if (!text) {
          if (e) e.preventDefault();
          return false;
        }
        var html = quillInstance.getSemanticHTML ? quillInstance.getSemanticHTML() : quillInstance.root.innerHTML;
        document.getElementById('content-input').value = html;
      }
      return true;
    }

    function showCompose() {
      document.getElementById('edit-id-input').value = '';
      document.getElementById('edit-banner').style.display = 'none';
      document.getElementById('submit-btn').textContent = 'Publish';
      document.getElementById('content-input').value = '';
      document.getElementById('public1-input').checked = false;
      document.getElementById('public2-input').checked = false;
      if (quillInstance) {
        quillInstance.setText('');
      }
      document.getElementById('compose-section').style.display = 'block';
      document.getElementById('compose-btn').style.display = 'none';
      if (currentMode === 'html' && quillInstance) {
        quillInstance.focus();
      } else {
        document.getElementById('content-input').focus();
      }
    }

    function startEdit(btn) {
      var id = btn.getAttribute('data-id') || '';
      var fmt = btn.getAttribute('data-format') || 'text';
      var isPub = btn.getAttribute('data-public') === '1';
      var content = btn.getAttribute('data-content') || '';

      document.getElementById('edit-id-input').value = id;
      document.getElementById('edit-id-display').textContent = id;
      document.getElementById('edit-banner').style.display = 'block';
      document.getElementById('submit-btn').textContent = 'Save Changes';
      document.getElementById('public1-input').checked = isPub;
      document.getElementById('public2-input').checked = isPub;

      document.getElementById('compose-section').style.display = 'block';
      document.getElementById('compose-btn').style.display = 'none';

      setEditorMode(fmt);
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
      document.getElementById('compose-section').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function hideCompose() {
      document.getElementById('edit-id-input').value = '';
      document.getElementById('edit-banner').style.display = 'none';
      document.getElementById('compose-section').style.display = 'none';
      document.getElementById('compose-btn').style.display = 'inline-block';
    }
    function doLogout(e) {
      if (e) e.preventDefault();
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "/logout", true, "logout", "logout");
      xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
      xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
          window.location.href = "/";
        }
      };
      xhr.send();
      return false;
    }
  </script>
</body>
</html>
`

