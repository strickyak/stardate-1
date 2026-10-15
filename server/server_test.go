package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCalculateStardate(t *testing.T) {
	// Start of year 2026 should be close to 26000.00
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sd1 := CalculateStardate(t1)
	if sd1 < 25999.9 || sd1 > 26000.1 {
		t.Errorf("expected ~26000.00, got %f", sd1)
	}

	// Mid-year 2026 should be close to 26500.00
	t2 := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	sd2 := CalculateStardate(t2)
	if sd2 < 26490.0 || sd2 > 26510.0 {
		t.Errorf("expected ~26500.00, got %f", sd2)
	}
}

func TestPasswordPrefixAuth(t *testing.T) {
	site := &Site{
		handle: "localhost",
		cfg: SiteConfig{
			Password: "starfleet",
			Salt:     "some-arbitrary-string",
		},
	}

	tests := []struct {
		name       string
		username   string
		password   string
		wantAuth   bool
		wantCrypto bool
		wantUser   string
	}{
		{
			name:       "exact match",
			username:   "alice",
			password:   "starfleet",
			wantAuth:   true,
			wantCrypto: false,
			wantUser:   "alice",
		},
		{
			name:       "crypto user with / and 12 ASCII chars",
			username:   "spock",
			password:   "starfleet/123456789012",
			wantAuth:   true,
			wantCrypto: true,
		},
		{
			name:       "crypto user with / and 16 ASCII chars",
			username:   "spock",
			password:   "starfleet/vulcan_long_pass",
			wantAuth:   true,
			wantCrypto: true,
		},
		{
			name:       "rejected: / with only 11 ASCII chars",
			username:   "spock",
			password:   "starfleet/12345678901",
			wantAuth:   false,
		},
		{
			name:       "rejected: extra chars without /",
			username:   "alice",
			password:   "starfleet1234567890123",
			wantAuth:   false,
		},
		{
			name:       "rejected: non-ASCII in secret part",
			username:   "spock",
			password:   "starfleet/12345678901é",
			wantAuth:   false,
		},
		{
			name:       "shorter than shared password",
			username:   "alice",
			password:   "starflee",
			wantAuth:   false,
		},
		{
			name:       "different password same length",
			username:   "alice",
			password:   "startrek1",
			wantAuth:   false,
		},
		{
			name:       "wrong prefix but long",
			username:   "alice",
			password:   "enterprise/123456789012",
			wantAuth:   false,
		},
		{
			name:       "empty username",
			username:   "",
			password:   "starfleet",
			wantAuth:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)
			if tc.username != "" || tc.password != "" {
				req.SetBasicAuth(tc.username, tc.password)
			}
			auth, ok := site.Authenticate(req)
			if ok != tc.wantAuth {
				t.Fatalf("Authenticate() ok = %v, want %v", ok, tc.wantAuth)
			}
			if tc.wantAuth {
				if auth.IsCrypto != tc.wantCrypto {
					t.Errorf("auth.IsCrypto = %v, want %v", auth.IsCrypto, tc.wantCrypto)
				}
				if !tc.wantCrypto && auth.EffectiveUser != tc.wantUser {
					t.Errorf("auth.EffectiveUser = %s, want %s", auth.EffectiveUser, tc.wantUser)
				}
				if tc.wantCrypto {
					expectedCrypto, _ := DeriveCryptoIdentity(site.cfg.Salt, tc.username, tc.password)
					if auth.EffectiveUser != expectedCrypto {
						t.Errorf("auth.EffectiveUser = %s, want %s", auth.EffectiveUser, expectedCrypto)
					}
				}
			}
		})
	}
}

func TestServerHTTPSAndMicroblog(t *testing.T) {
	const sharedPW = "stardate-secret-pw"
	const testSalt = "some-arbitrary-string"
	cfg := ServerConfig{
		Addr: "127.0.0.1:0", // random available port
		Sites: map[string]SiteConfig{
			"127.0.0.1": {
				Password: sharedPW,
				Salt:     testSalt,
			},
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	go func() {
		_ = srv.Start()
	}()

	// Wait for listener to be active
	for i := 0; i < 50; i++ {
		if srv.listener != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.listener == nil {
		t.Fatal("timed out waiting for server listener")
	}

	baseURL := "https://" + srv.Addr()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}

	// 1. Check healthz
	resp, err := client.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		t.Fatalf("unexpected healthz response: %d, body: %q", resp.StatusCode, body)
	}

	// 2. Anonymous access to root:
	// Should show LOGIN button and no "New Note" compose button
	resp, err = client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "LOGIN") {
		t.Errorf("expected anonymous page to contain LOGIN button")
	}
	if strings.Contains(bodyStr, `id="compose-section"`) || strings.Contains(bodyStr, `id="compose-btn"`) {
		t.Errorf("anonymous page should not contain compose section or compose button")
	}

	// 3. GET /login without credentials should return 401 Unauthorized
	resp, err = client.Get(baseURL + "/login")
	if err != nil {
		t.Fatalf("GET /login failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on /login without credentials, got %d", resp.StatusCode)
	}
	authHeader := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(authHeader, `Basic realm="stardate"`) {
		t.Errorf("expected WWW-Authenticate Basic header, got %q", authHeader)
	}

	// 4. GET /login with non-matching password should return 401
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/login", nil)
	req.SetBasicAuth("alice", "wrong-password")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /login with wrong password failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong password, got %d", resp.StatusCode)
	}

	// 5. GET /login with extra chars not matching "/" + >=12 ASCII chars should return 401
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/login", nil)
	req.SetBasicAuth("alice", sharedPW+"/short")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /login with short secret failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for short secret after /, got status %d", resp.StatusCode)
	}

	// Exact match with sharedPW succeeds
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/login", nil)
	req.SetBasicAuth("alice", sharedPW)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /login with exact sharedPW failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Errorf("expected redirect from /login, got status %d", resp.StatusCode)
	}

	// 6. Alice posts a public message (requires both public1 and public2 checked)
	formAlicePub := url.Values{
		"content": {"Captains log, stardate test: public announcement"},
		"public1": {"1"},
		"public2": {"1"},
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/post", strings.NewReader(formAlicePub.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("alice", sharedPW)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("POST /post failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected 303 after post, got %d", resp.StatusCode)
	}

	// 7. Alice posts a note with only ONE checkbox checked -> must default to private
	formAlicePriv := url.Values{
		"content": {"Alice's secret notes: standard private"},
		"public1": {"1"},
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/post", strings.NewReader(formAlicePriv.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("alice", sharedPW)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("POST /post private failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected 303 after private post, got %d", resp.StatusCode)
	}

	// 8. Crypto user (spock) logs in with SharedPassword + "/" + >= 12 ASCII chars
	spockPass := sharedPW + "/vulcanmindmeld" // "/" + 14 ASCII characters (>= 12)
	expectedCryptoUser, expectedKey := DeriveCryptoIdentity(testSalt, "spock", spockPass)

	// Spock posts a message with no checkboxes checked -> defaults to private and encrypted
	secretPlaintext := "Vulcan high command: classified sensor telemetry"
	formSpockPriv := url.Values{
		"content": {secretPlaintext},
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/post", strings.NewReader(formSpockPriv.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("spock", spockPass)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Spock POST /post failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected 303 after crypto post, got %d", resp.StatusCode)
	}

	// 9. Inspect raw stored message in store to verify encryption and Base64 representation
	recentRaw := srv.Site("127.0.0.1").Store().GetRecent(expectedCryptoUser, 10)
	var spockRawMsg *Message
	for _, m := range recentRaw {
		if m.Author == expectedCryptoUser && !m.IsPublic {
			spockRawMsg = &m
			break
		}
	}
	if spockRawMsg == nil {
		t.Fatalf("could not find stored raw message for crypto user %s", expectedCryptoUser)
	}

	// The stored content MUST NOT be the plaintext
	if spockRawMsg.Content == secretPlaintext {
		t.Fatal("stored private message content was NOT encrypted!")
	}

	// The stored content MUST be valid Base64
	if _, err := base64.StdEncoding.DecodeString(spockRawMsg.Content); err != nil {
		t.Fatalf("stored private message is not valid Base64: %v", err)
	}

	// Verify decrypting with the derived key recovers the original message
	recovered, err := DecryptMessage(spockRawMsg.Content, expectedKey)
	if err != nil {
		t.Fatalf("manual DecryptMessage failed: %v", err)
	}
	if recovered != secretPlaintext {
		t.Errorf("expected recovered plaintext %q, got %q", secretPlaintext, recovered)
	}

	// 10. Verify Spock accessing GET / displays the DECRYPTED message
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/?format=json", nil)
	req.SetBasicAuth("spock", spockPass)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /?format=json for spock failed: %v", err)
	}
	var spockJSON StardateResponse
	_ = json.NewDecoder(resp.Body).Decode(&spockJSON)
	resp.Body.Close()

	if !spockJSON.IsCrypto {
		t.Errorf("expected is_crypto=true in JSON response for spock")
	}
	if spockJSON.User != expectedCryptoUser {
		t.Errorf("expected user=%s, got %s", expectedCryptoUser, spockJSON.User)
	}

	foundDecrypted := false
	for _, m := range spockJSON.Messages {
		if !m.IsPublic && m.Author == expectedCryptoUser {
			if m.Content == secretPlaintext {
				foundDecrypted = true
			}
		}
	}
	if !foundDecrypted {
		t.Errorf("expected Spock's JSON response to contain decrypted message %q", secretPlaintext)
	}

	// 11. Verify Spock HTML page contains Crypto badge and decrypted text
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/", nil)
	req.SetBasicAuth("spock", spockPass)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET / for spock failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	spockHTML := string(body)
	if !strings.Contains(spockHTML, expectedCryptoUser) {
		t.Errorf("expected HTML to show crypto username %s", expectedCryptoUser)
	}
	if !strings.Contains(spockHTML, secretPlaintext) {
		t.Errorf("expected HTML to show decrypted plaintext for crypto user")
	}

	// 12. Verify Alice cannot see Spock's private encrypted message
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/?format=json", nil)
	req.SetBasicAuth("alice", sharedPW)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /?format=json for alice failed: %v", err)
	}
	var aliceJSON StardateResponse
	_ = json.NewDecoder(resp.Body).Decode(&aliceJSON)
	resp.Body.Close()

	for _, m := range aliceJSON.Messages {
		if m.Author == expectedCryptoUser && !m.IsPublic {
			t.Errorf("Alice must not see Spock's private message: %+v", m)
		}
	}

	// 13. Verify anonymous cannot see Spock's private encrypted message
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/?format=json", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /?format=json for anon failed: %v", err)
	}
	var anonJSON StardateResponse
	_ = json.NewDecoder(resp.Body).Decode(&anonJSON)
	resp.Body.Close()

	for _, m := range anonJSON.Messages {
		if !m.IsPublic {
			t.Errorf("Anonymous must not see any private message: %+v", m)
		}
	}

	// 14. Test Logout flow
	// User visits /logout: should return 303 redirect (never 401) and set stardate_logout cookie
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/logout", nil)
	req.SetBasicAuth("spock", spockPass)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /logout failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect on logout, got %d", resp.StatusCode)
	}
	var logoutCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "stardate_logout" {
			logoutCookie = c
			break
		}
	}
	if logoutCookie == nil || logoutCookie.Value != "1" {
		t.Fatalf("expected stardate_logout=1 cookie on logout, got %+v", logoutCookie)
	}

	// Even if the browser replays cached Basic Auth credentials, the presence of stardate_logout
	// ensures the user is treated as logged out
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/", nil)
	req.SetBasicAuth("spock", spockPass)
	req.AddCookie(logoutCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET / after logout failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "LOGIN") {
		t.Errorf("expected LOGIN button after logout")
	}
	if strings.Contains(string(body), `id="compose-section"`) {
		t.Errorf("expected compose section to be hidden after logout")
	}

	// Screen refresh: sending same cookie and credentials again keeps user logged out
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/", nil)
	req.SetBasicAuth("spock", spockPass)
	req.AddCookie(logoutCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET / on refresh failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "LOGIN") {
		t.Errorf("expected user to remain logged out on screen refresh")
	}

	// Shutdown server
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

func TestServerHTTPPort(t *testing.T) {
	const sharedPW = "http-test-pw"
	cfg := ServerConfig{
		HTTPSAddr: "127.0.0.1:0",
		HTTPAddr:  "127.0.0.1:0",
		Sites: map[string]SiteConfig{
			"127.0.0.1": {
				Password: sharedPW,
			},
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	go func() {
		_ = srv.Start()
	}()

	for i := 0; i < 50; i++ {
		if srv.listener != nil && srv.httpListener != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.httpListener == nil {
		t.Fatal("timed out waiting for HTTP listener")
	}

	httpURL := "http://" + srv.HTTPAddr()
	resp, err := http.Get(httpURL + "/healthz")
	if err != nil {
		t.Fatalf("GET %s/healthz failed: %v", httpURL, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		t.Fatalf("unexpected HTTP healthz response: %d, body: %q", resp.StatusCode, body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

func TestPWFileAuthentication(t *testing.T) {
	testDir := filepath.Join(".", ".test_tmp")
	_ = os.RemoveAll(testDir)
	siteDir := filepath.Join(testDir, "yak.net")
	if err := os.MkdirAll(siteDir, 0755); err != nil {
		t.Fatalf("failed to create site dir: %v", err)
	}
	defer os.RemoveAll(testDir)

	const testSalt = "federation-salt"
	kirkPW := "kobayashi"
	kirkHash := HashPassword(testSalt, kirkPW)

	cfgBytes := []byte(`{"salt": "federation-salt"}` + "\n")
	if err := os.WriteFile(filepath.Join(siteDir, SiteConfigFilename), cfgBytes, 0600); err != nil {
		t.Fatalf("failed to write config.json: %v", err)
	}

	pwFilePath := filepath.Join(siteDir, SitePWFilename)
	jsonlContent := strings.Join([]string{
		`{"handle": "Spock_01", "display": "Spock 🖖", "pw": "llap"}`,
		`{"handle": "Kirk", "pwhash": "` + kirkHash + `"}`,
		"",
	}, "\n")
	if err := os.WriteFile(pwFilePath, []byte(jsonlContent), 0600); err != nil {
		t.Fatalf("failed to write pwfile: %v", err)
	}

	// Note: pw is empty in config.json, so shared password logins are disabled
	srv, err := New(ServerConfig{
		HTTPAddr: "127.0.0.1:0",
		Dir:      testDir,
	})
	if err != nil {
		t.Fatalf("New() with valid site pwfile.jsonl failed: %v", err)
	}
	site := srv.Site("yak.net")
	if site == nil {
		t.Fatalf("expected site yak.net to be loaded")
	}

	tests := []struct {
		name       string
		username   string
		password   string
		wantAuth   bool
		wantCrypto bool
		wantUser   string
		normHandle string
	}{
		{
			name:       "pwfile plaintext pw with unicode display and case-insensitive handle",
			username:   "SPOCK_01",
			password:   "llap",
			wantAuth:   true,
			wantCrypto: false,
			wantUser:   "Spock 🖖",
			normHandle: "spock_01",
		},
		{
			name:       "pwfile plaintext pw crypto login uses 10-hex crypto username",
			username:   "Spock_01",
			password:   "llap/vulcan_secret_123",
			wantAuth:   true,
			wantCrypto: true,
			normHandle: "spock_01",
		},
		{
			name:     "pwfile plaintext pw crypto login rejected when secret < 12 chars",
			username: "spock_01",
			password: "llap/short",
			wantAuth: false,
		},
		{
			name:       "pwfile pwhash login without display uses normalized handle",
			username:   "KIRK",
			password:   kirkPW,
			wantAuth:   true,
			wantCrypto: false,
			wantUser:   "kirk",
			normHandle: "kirk",
		},
		{
			name:       "pwfile pwhash crypto login",
			username:   "Kirk",
			password:   kirkPW + "/maru_override_123",
			wantAuth:   true,
			wantCrypto: true,
			normHandle: "kirk",
		},
		{
			name:     "pwfile wrong password rejected",
			username: "kirk",
			password: "wrongpassword",
			wantAuth: false,
		},
		{
			name:     "unknown user rejected when pw is empty",
			username: "mccoy",
			password: "llap",
			wantAuth: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://yak.net/", nil)
			req.SetBasicAuth(tc.username, tc.password)
			auth, ok := site.Authenticate(req)
			if ok != tc.wantAuth {
				t.Fatalf("Authenticate() ok = %v, want %v", ok, tc.wantAuth)
			}
			if !tc.wantAuth {
				return
			}
			if auth.IsCrypto != tc.wantCrypto {
				t.Errorf("auth.IsCrypto = %v, want %v", auth.IsCrypto, tc.wantCrypto)
			}
			if !tc.wantCrypto {
				if auth.EffectiveUser != tc.wantUser {
					t.Errorf("auth.EffectiveUser = %q, want %q", auth.EffectiveUser, tc.wantUser)
				}
			} else {
				expectedCrypto, expectedKey := DeriveCryptoIdentity(testSalt, tc.normHandle, tc.password)
				if auth.EffectiveUser != expectedCrypto {
					t.Errorf("crypto EffectiveUser = %q, want %q", auth.EffectiveUser, expectedCrypto)
				}
				if string(auth.CryptoKey) != string(expectedKey) {
					t.Errorf("crypto key mismatch")
				}
			}
		})
	}

	// Verify invalid handle in pwfile.jsonl is rejected on load
	badSiteDir := filepath.Join(testDir, "bad.yak.net")
	_ = os.MkdirAll(badSiteDir, 0755)
	_ = os.WriteFile(filepath.Join(badSiteDir, SiteConfigFilename), []byte(`{}`), 0600)
	if err := os.WriteFile(filepath.Join(badSiteDir, SitePWFilename), []byte(`{"handle": "bad-handle!", "pw": "secret"}`+"\n"), 0600); err != nil {
		t.Fatalf("failed to write bad pwfile: %v", err)
	}
	if _, err := New(ServerConfig{HTTPAddr: "127.0.0.1:0", Dir: testDir}); err == nil {
		t.Errorf("expected error loading site pwfile.jsonl with invalid handle 'bad-handle!', got nil")
	}
}

func TestSuperuserFeatures(t *testing.T) {
	testDir := filepath.Join(".", ".test_tmp_su")
	_ = os.RemoveAll(testDir)
	siteDir := filepath.Join(testDir, "127.0.0.1")
	if err := os.MkdirAll(siteDir, 0755); err != nil {
		t.Fatalf("failed to create site dir: %v", err)
	}
	defer os.RemoveAll(testDir)

	cfgPath := filepath.Join(siteDir, SiteConfigFilename)
	pwFilePath := filepath.Join(siteDir, SitePWFilename)
	dataFilePath := filepath.Join(siteDir, DirMicrologs, "1.json")

	if err := os.WriteFile(cfgPath, []byte(`{"salt":"enterprise-d"}`+"\n"), 0600); err != nil {
		t.Fatalf("failed to write config.json: %v", err)
	}

	jsonlContent := strings.Join([]string{
		`{"handle":"picard","display":"Capt. Picard","pw":"engage","superuser":true}`,
		`{"handle":"riker","display":"Cmdr. Riker","pw":"number1"}`,
		"",
	}, "\n")
	if err := os.WriteFile(pwFilePath, []byte(jsonlContent), 0600); err != nil {
		t.Fatalf("failed to write pwfile: %v", err)
	}

	srv, err := New(ServerConfig{
		HTTPAddr: "127.0.0.1:0",
		Dir:      testDir,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	go func() {
		_ = srv.Start()
	}()
	for i := 0; i < 50; i++ {
		if srv.httpListener != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.httpListener == nil {
		t.Fatal("timed out waiting for HTTP listener")
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	baseURL := "http://" + srv.HTTPAddr()
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}

	// 1. Riker posts a public message (id=1) and a private message (id=2)
	formPub := url.Values{
		"content": {"Riker's original public log"},
		"format":  {"text"},
		"public1": {"1"},
		"public2": {"1"},
	}
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/post", strings.NewReader(formPub.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("riker", "number1")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("riker public post failed: err=%v status=%v", err, resp)
	}
	resp.Body.Close()

	formPriv := url.Values{
		"content": {"Riker's private holodeck schedule"},
		"format":  {"text"},
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/post", strings.NewReader(formPriv.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("riker", "number1")
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("riker private post failed: err=%v status=%v", err, resp)
	}
	resp.Body.Close()

	// 2. Superuser (picard) edits Riker's public message (id=1)
	editPub := url.Values{
		"edit_id": {"1"},
		"content": {"Riker's public log [Amended by Captain Picard]"},
		"format":  {"text"},
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/post", strings.NewReader(editPub.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("picard", "engage")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("superuser edit public post failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected 303 when superuser edits public post, got %d", resp.StatusCode)
	}

	// Verify message #1 was updated and remained public & authored by Cmdr. Riker
	m1, ok := srv.Site("127.0.0.1").Store().GetByID(1)
	if !ok || m1.Content != "Riker's public log [Amended by Captain Picard]" || !m1.IsPublic || m1.Author != "Cmdr. Riker" {
		t.Errorf("unexpected message #1 after superuser edit: %+v", m1)
	}

	// Superuser cannot edit Riker's private message (id=2)
	editPriv := url.Values{
		"edit_id": {"2"},
		"content": {"Captain peeking"},
		"format":  {"text"},
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/post", strings.NewReader(editPriv.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("picard", "engage")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("superuser edit private post request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 when superuser attempts to edit another user's private post, got %d", resp.StatusCode)
	}

	// 3. Non-superuser (riker) cannot hide posts or access user management endpoints
	hideForm := url.Values{"id": {"1"}}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/hide", strings.NewReader(hideForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("riker", "number1")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("non-superuser hide request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 when non-superuser calls /hide, got %d", resp.StatusCode)
	}

	// 4. Superuser (picard) hides post id=1
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/hide", strings.NewReader(hideForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("picard", "engage")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("superuser hide request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected 303 when superuser hides post, got %d", resp.StatusCode)
	}

	// Verify micrologs/1.json has "hidden": true on message #1
	rawJSONBytes, err := os.ReadFile(dataFilePath)
	if err != nil {
		t.Fatalf("failed to read micrologs/1.json: %v", err)
	}
	if !strings.Contains(string(rawJSONBytes), `"hidden": true`) {
		t.Errorf("expected micrologs/1.json to contain '\"hidden\": true', got:\n%s", string(rawJSONBytes))
	}

	// Verify LOG (GetRecent and GET /) does not display hidden post #1
	recent := srv.Site("127.0.0.1").Store().GetRecent("Cmdr. Riker", 10)
	for _, m := range recent {
		if m.ID == 1 {
			t.Errorf("expected hidden post #1 to be excluded from GetRecent, but found it")
		}
	}

	// 5. Superuser adds a new user ("worf") via User Dashboard (POST /users)
	addUserForm := url.Values{
		"handle":  {"Worf"},
		"display": {"Lt. Worf"},
		"pw":      {"prune_juice"},
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/users", strings.NewReader(addUserForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("picard", "engage")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("superuser add user failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected 303 after adding user, got %d", resp.StatusCode)
	}

	// Check pwfile contents: "superuser":true should ONLY appear on picard's line
	pwFileBytes, err := os.ReadFile(pwFilePath)
	if err != nil {
		t.Fatalf("failed to read pwfile: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(pwFileBytes)), "\n") {
		if strings.Contains(line, `"worf"`) || strings.Contains(line, `"riker"`) {
			if strings.Contains(line, `"superuser"`) {
				t.Errorf("non-superuser line must not contain 'superuser' attribute: %s", line)
			}
		}
		if strings.Contains(line, `"picard"`) {
			if !strings.Contains(line, `"superuser":true`) {
				t.Errorf("superuser line must contain '\"superuser\":true': %s", line)
			}
		}
	}

	// Verify newly added user "worf" can immediately authenticate
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/?format=json", nil)
	req.SetBasicAuth("worf", "prune_juice")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("worf login check failed: %v", err)
	}
	var worfResp StardateResponse
	_ = json.NewDecoder(resp.Body).Decode(&worfResp)
	resp.Body.Close()
	if worfResp.User != "Lt. Worf" {
		t.Errorf("expected worf authenticated user 'Lt. Worf', got %q", worfResp.User)
	}

	// 6. Superuser disables user "riker" via User Dashboard (POST /users/disable)
	disableForm := url.Values{
		"handle":   {"riker"},
		"disabled": {"1"},
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/users/disable", strings.NewReader(disableForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("picard", "engage")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("superuser disable user failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected 303 after disabling user, got %d", resp.StatusCode)
	}

	// Verify riker can no longer authenticate (GET /login returns 401)
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/login", nil)
	req.SetBasicAuth("riker", "number1")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("disabled riker login request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for disabled user riker, got %d", resp.StatusCode)
	}

	// Verify pwfile has "disabled":true on riker's line
	pwFileBytes, _ = os.ReadFile(pwFilePath)
	if !strings.Contains(string(pwFileBytes), `"disabled":true`) {
		t.Errorf("expected pwfile to contain '\"disabled\":true', got:\n%s", string(pwFileBytes))
	}
}

func TestSiteTitleAndHideStardates(t *testing.T) {
	srv, err := New(ServerConfig{
		HTTPAddr: "127.0.0.1:0",
		Sites: map[string]SiteConfig{
			"127.0.0.1": {
				Password:      "secret",
				HideStardates: true,
				SiteTitle:     "Captain's Journal 🚀",
			},
		},
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, _ = srv.Site("127.0.0.1").Store().Add("kirk", "Testing custom site title and hidden stardates", true)

	go func() {
		_ = srv.Start()
	}()
	for i := 0; i < 50; i++ {
		if srv.httpListener != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.httpListener == nil {
		t.Fatal("timed out waiting for HTTP listener")
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	resp, err := http.Get("http://" + srv.HTTPAddr() + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	if !strings.Contains(html, "<h1>Captain&#39;s Journal 🚀</h1>") {
		t.Errorf("expected custom unicode site title in <h1>, got:\n%s", html)
	}
	if strings.Contains(html, `<div class="stardate-live">`) || strings.Contains(html, `<span class="stardate-tag">`) {
		t.Errorf("expected stardates to be hidden when HideStardates=true, got:\n%s", html)
	}
}

func TestMultiSiteRoutingAndDirectories(t *testing.T) {
	testDir := filepath.Join(".", ".test_tmp_multisite")
	_ = os.RemoveAll(testDir)
	defer os.RemoveAll(testDir)

	yakDir := filepath.Join(testDir, "yak.net")
	jbDir := filepath.Join(testDir, "jeanbowe.com")
	if err := os.MkdirAll(yakDir, 0755); err != nil {
		t.Fatalf("mkdir yak.net failed: %v", err)
	}
	if err := os.MkdirAll(jbDir, 0755); err != nil {
		t.Fatalf("mkdir jeanbowe.com failed: %v", err)
	}

	// Write per-site config.json
	if err := os.WriteFile(filepath.Join(yakDir, SiteConfigFilename), []byte(`{"pw":"yakpass","site_title":"Yak Net 🦬"}`), 0600); err != nil {
		t.Fatalf("write yak.net/config.json failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(jbDir, SiteConfigFilename), []byte(`{"pw":"jbpass","site_title":"Jean Bowe","hide_stardates":true}`), 0600); err != nil {
		t.Fatalf("write jeanbowe.com/config.json failed: %v", err)
	}

	srv, err := New(ServerConfig{
		HTTPAddr: "127.0.0.1:0",
		Dir:      testDir,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	go func() {
		_ = srv.Start()
	}()
	for i := 0; i < 50; i++ {
		if srv.httpListener != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.httpListener == nil {
		t.Fatal("timed out waiting for HTTP listener")
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	baseURL := "http://" + srv.HTTPAddr()
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}

	// 1. Unknown hostname (127.0.0.1 is not in testDir) should return 404
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET / for unknown host failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for unknown host 127.0.0.1, got %d", resp.StatusCode)
	}

	// 2. Post to yak.net using Host header with leading "www." ("www.yak.net")
	postYak := url.Values{
		"content": {"Hello from Yak Net!"},
		"public1": {"1"},
		"public2": {"1"},
	}
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/post", strings.NewReader(postYak.Encode()))
	req.Host = "www.yak.net"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("strick", "yakpass")
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST to www.yak.net failed: err=%v status=%v", err, resp)
	}
	resp.Body.Close()

	// 3. Post to jeanbowe.com using "/@jeanbowe.com/post" URL override (even though Host is 127.0.0.1)
	postJB := url.Values{
		"content": {"Hello from Jean Bowe via @ override!"},
		"public1": {"1"},
		"public2": {"1"},
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/@jeanbowe.com/post", strings.NewReader(postJB.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("jean", "jbpass")
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST to /@jeanbowe.com/post failed: err=%v status=%v", err, resp)
	}
	if loc := resp.Header.Get("Location"); loc != "/@jeanbowe.com/" {
		t.Errorf("expected redirect Location '/@jeanbowe.com/', got %q", loc)
	}
	resp.Body.Close()

	// 4. Verify yak.net page has Yak Net title and message, and NOT Jean Bowe's message
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/", nil)
	req.Host = "yak.net"
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET yak.net failed: %v", err)
	}
	yakBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	yakHTML := string(yakBody)
	if !strings.Contains(yakHTML, "<h1>Yak Net 🦬</h1>") || !strings.Contains(yakHTML, "Hello from Yak Net!") {
		t.Errorf("unexpected yak.net HTML:\n%s", yakHTML)
	}
	if strings.Contains(yakHTML, "Hello from Jean Bowe") {
		t.Errorf("yak.net must not show jeanbowe.com messages")
	}

	// 5. Verify /@jeanbowe.com/ page has Jean Bowe title, message, hidden stardates, and /@jeanbowe.com action links
	resp, err = client.Get(baseURL + "/@jeanbowe.com/")
	if err != nil {
		t.Fatalf("GET /@jeanbowe.com/ failed: %v", err)
	}
	jbBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	jbHTML := string(jbBody)
	if !strings.Contains(jbHTML, "<h1>Jean Bowe</h1>") || !strings.Contains(jbHTML, "Hello from Jean Bowe via @ override!") {
		t.Errorf("unexpected jeanbowe.com HTML:\n%s", jbHTML)
	}
	if !strings.Contains(jbHTML, `href="/@jeanbowe.com/login"`) {
		t.Errorf("expected login link to use /@jeanbowe.com/login")
	}
	if strings.Contains(jbHTML, `<div class="stardate-live">`) {
		t.Errorf("expected stardates to be hidden on jeanbowe.com")
	}

	// 6. Verify micrologs/1.json files were persisted in their respective site subdirectories
	if _, err := os.Stat(filepath.Join(yakDir, DirMicrologs, "1.json")); err != nil {
		t.Errorf("expected yak.net/micrologs/1.json to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(jbDir, DirMicrologs, "1.json")); err != nil {
		t.Errorf("expected jeanbowe.com/micrologs/1.json to exist: %v", err)
	}
}

func TestPostingFlavorsStarredAndGallery(t *testing.T) {
	testDir := filepath.Join(".", ".test_tmp_flavors")
	_ = os.RemoveAll(testDir)
	defer os.RemoveAll(testDir)

	siteDir := filepath.Join(testDir, "yak.net")
	if err := os.MkdirAll(siteDir, 0755); err != nil {
		t.Fatalf("mkdir yak.net failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(siteDir, SiteConfigFilename), []byte(`{"pw":"secret","site_title":"Yak Net"}`), 0600); err != nil {
		t.Fatalf("write config.json failed: %v", err)
	}

	srv, err := New(ServerConfig{
		HTTPAddr: "127.0.0.1:0",
		Dir:      testDir,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	go func() {
		_ = srv.Start()
	}()
	for i := 0; i < 50; i++ {
		if srv.httpListener != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.httpListener == nil {
		t.Fatal("timed out waiting for HTTP listener")
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	baseURL := "http://" + srv.HTTPAddr()
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}

	// 1. Create a standard "log" post (default flavor) - even if is_starred=1 is passed, log posts must have is_starred: false
	logForm := url.Values{
		"flavor":     {"log"},
		"content":    {"Just a quick log entry"},
		"is_starred": {"1"},
		"public1":    {"1"},
		"public2":    {"1"},
	}
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/@yak.net/post", strings.NewReader(logForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("kirk", "secret")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST log failed: err=%v status=%v", err, resp)
	}
	resp.Body.Close()

	// 2. Create an "article" post with title, two paragraphs separated by blank line, attachment, and is_starred=true
	var artBuf bytes.Buffer
	artMW := multipart.NewWriter(&artBuf)
	_ = artMW.WriteField("flavor", "article")
	_ = artMW.WriteField("title", "Warp Field Dynamics")
	_ = artMW.WriteField("content", "Detailed first paragraph about warp coils.\n\nSecond paragraph with subspace equations.")
	_ = artMW.WriteField("format", "markdown")
	_ = artMW.WriteField("is_starred", "1")
	_ = artMW.WriteField("public1", "1")
	_ = artMW.WriteField("public2", "1")
	afw, err := artMW.CreateFormFile("attachments", "telemetry.txt")
	if err != nil {
		t.Fatalf("CreateFormFile attachments failed: %v", err)
	}
	fakeTelemetry := []byte("TELEMETRY_LOG_DATA_99")
	_, _ = afw.Write(fakeTelemetry)
	_ = artMW.Close()

	req, _ = http.NewRequest(http.MethodPost, baseURL+"/@yak.net/post", &artBuf)
	req.Header.Set("Content-Type", artMW.FormDataContentType())
	req.SetBasicAuth("spock", "secret")
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST article failed: err=%v status=%v", err, resp)
	}
	resp.Body.Close()

	// 3. Create a "gallery" post with multipart image upload and is_starred=false
	var bodyBuf bytes.Buffer
	mw := multipart.NewWriter(&bodyBuf)
	_ = mw.WriteField("flavor", "gallery")
	_ = mw.WriteField("title", "Nebula Photos")
	_ = mw.WriteField("content", "Captured by long-range sensors.")
	_ = mw.WriteField("public1", "1")
	_ = mw.WriteField("public2", "1")
	fw, err := mw.CreateFormFile("images", "nebula.png")
	if err != nil {
		t.Fatalf("CreateFormFile failed: %v", err)
	}
	fakePNG := []byte("FAKE_PNG_IMAGE_BYTES_12345")
	_, _ = fw.Write(fakePNG)
	_ = mw.Close()

	req, _ = http.NewRequest(http.MethodPost, baseURL+"/@yak.net/post", &bodyBuf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.SetBasicAuth("uhura", "secret")
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST gallery failed: err=%v status=%v", err, resp)
	}
	resp.Body.Close()

	// 4. Verify separate JSON files in micrologs/1.json, articles/2.json, and galleries/3.json
	rawLogJSON, err := os.ReadFile(filepath.Join(siteDir, DirMicrologs, "1.json"))
	if err != nil {
		t.Fatalf("failed to read micrologs/1.json: %v", err)
	}
	if !strings.Contains(string(rawLogJSON), `"flavor": "log"`) || !strings.Contains(string(rawLogJSON), `"is_starred": false`) {
		t.Errorf("unexpected micrologs/1.json:\n%s", string(rawLogJSON))
	}

	rawArticleJSON, err := os.ReadFile(filepath.Join(siteDir, DirArticles, "2.json"))
	if err != nil {
		t.Fatalf("failed to read articles/2.json: %v", err)
	}
	if !strings.Contains(string(rawArticleJSON), `"flavor": "article"`) || !strings.Contains(string(rawArticleJSON), `"is_starred": true`) || !strings.Contains(string(rawArticleJSON), "Second paragraph with subspace equations.") || !strings.Contains(string(rawArticleJSON), `"telemetry.txt"`) {
		t.Errorf("unexpected articles/2.json:\n%s", string(rawArticleJSON))
	}

	rawGalleryJSON, err := os.ReadFile(filepath.Join(siteDir, DirGalleries, "3.json"))
	if err != nil {
		t.Fatalf("failed to read galleries/3.json: %v", err)
	}
	if !strings.Contains(string(rawGalleryJSON), `"flavor": "gallery"`) || !strings.Contains(string(rawGalleryJSON), `"nebula.png"`) {
		t.Errorf("unexpected galleries/3.json:\n%s", string(rawGalleryJSON))
	}

	// Verify in-RAM state of article #2 only holds the first paragraph, while GetByID reads the full article from disk
	ramM2, ok := srv.Site("yak.net").Store().GetRAMByID(2)
	if !ok || ramM2.Content != "Detailed first paragraph about warp coils." || !ramM2.HasMore {
		t.Errorf("expected in-RAM article #2 to hold only first paragraph with HasMore=true, got %+v", ramM2)
	}

	// Verify via Store.GetByID that full posts are returned from disk
	m1, ok := srv.Site("yak.net").Store().GetByID(1)
	if !ok || m1.Flavor != FlavorLog || m1.IsStarred {
		t.Errorf("expected message #1 to be unstarred log, got %+v", m1)
	}
	m2, ok := srv.Site("yak.net").Store().GetByID(2)
	if !ok || m2.Flavor != FlavorArticle || !m2.IsStarred || m2.Title != "Warp Field Dynamics" || !strings.Contains(m2.Content, "Second paragraph with subspace equations.") || len(m2.Attachments) != 1 || m2.Attachments[0] != "telemetry.txt" {
		t.Errorf("expected message #2 from GetByID to be full starred article with telemetry.txt, got %+v", m2)
	}
	m3, ok := srv.Site("yak.net").Store().GetByID(3)
	if !ok || m3.Flavor != FlavorGallery || m3.IsStarred || len(m3.Images) != 1 || m3.Images[0] != "nebula.png" || len(m3.Attachments) != 0 {
		t.Errorf("expected message #3 to be unstarred gallery with nebula.png and no attachments, got %+v", m3)
	}

	// 5. Verify uploaded gallery image is in images/3/nebula.png and served at /@yak.net/images/3/nebula.png,
	// and article attachment is in attachments/2/telemetry.txt and served at /@yak.net/attachments/2/telemetry.txt
	if _, err := os.Stat(filepath.Join(siteDir, DirImages, "3", "nebula.png")); err != nil {
		t.Errorf("expected images/3/nebula.png on disk: %v", err)
	}
	if _, err := os.Stat(filepath.Join(siteDir, DirAttachments, "2", "telemetry.txt")); err != nil {
		t.Errorf("expected attachments/2/telemetry.txt on disk: %v", err)
	}

	imgResp, err := client.Get(baseURL + "/@yak.net/images/3/nebula.png")
	if err != nil {
		t.Fatalf("GET image failed: %v", err)
	}
	imgBytes, _ := io.ReadAll(imgResp.Body)
	imgResp.Body.Close()
	if imgResp.StatusCode != http.StatusOK || !bytes.Equal(imgBytes, fakePNG) {
		t.Errorf("unexpected image response: status=%d body=%q", imgResp.StatusCode, string(imgBytes))
	}

	attResp, err := client.Get(baseURL + "/@yak.net/attachments/2/telemetry.txt")
	if err != nil {
		t.Fatalf("GET attachment failed: %v", err)
	}
	attBytes, _ := io.ReadAll(attResp.Body)
	attResp.Body.Close()
	if attResp.StatusCode != http.StatusOK || !bytes.Equal(attBytes, fakeTelemetry) {
		t.Errorf("unexpected attachment response: status=%d body=%q", attResp.StatusCode, string(attBytes))
	}

	// 6. Verify HTML UI contains the creation flavor chooser, Starred section, gallery image,
	// UTC permalink link, first paragraph of article #2, MORE link, and NOT the second paragraph in the rendered summary
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/@yak.net/", nil)
	req.SetBasicAuth("kirk", "secret")
	pageResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /@yak.net/ failed: %v", err)
	}
	pageBytes, _ := io.ReadAll(pageResp.Body)
	pageResp.Body.Close()
	pageHTML := string(pageBytes)

	for _, needle := range []string{
		`id="flavor-chooser"`,
		`chooseFlavor('log')`,
		`chooseFlavor('article')`,
		`chooseFlavor('gallery')`,
		`Log Post`,
		`Article Page`,
		`Image Gallery`,
		`Starred Articles &amp; Galleries`,
		`Warp Field Dynamics`,
		`/@yak.net/images/3/nebula.png`,
		`/@yak.net/attachments/2/telemetry.txt`,
		`<a href="/@yak.net/2" class="permalink">`,
		`<a href="/@yak.net/2" class="more-link">MORE</a>`,
		`Detailed first paragraph about warp coils.`,
	} {
		if !strings.Contains(pageHTML, needle) {
			t.Errorf("expected HTML to contain %q", needle)
		}
	}
	if strings.Contains(pageHTML, "Second paragraph with subspace equations.") {
		t.Errorf("expected Recent Posts not to contain second paragraph of article #2 at all (since only first paragraph is in RAM)")
	}

	// 7. Verify permalink page /@yak.net/2 renders the full article (both paragraphs) from disk and back button
	permResp, err := client.Get(baseURL + "/@yak.net/2")
	if err != nil {
		t.Fatalf("GET /@yak.net/2 failed: %v", err)
	}
	permBytes, _ := io.ReadAll(permResp.Body)
	permResp.Body.Close()
	permHTML := string(permBytes)
	if permResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for /@yak.net/2, got %d", permResp.StatusCode)
	}
	for _, needle := range []string{
		`href="/@yak.net/" class="btn btn-primary">&larr; Recent Posts</a>`,
		`Warp Field Dynamics`,
		`Detailed first paragraph about warp coils.`,
		`Second paragraph with subspace equations.`,
	} {
		if !strings.Contains(permHTML, needle) {
			t.Errorf("expected permalink HTML to contain %q, got:\n%s", needle, permHTML)
		}
	}

	// Also verify ExtractArticleFirstParagraph with HTML <P> and <p>
	htmlSum, htmlMore := ExtractArticleFirstParagraph("First HTML para<P>Second HTML para", FormatHTML)
	if !htmlMore || !strings.Contains(string(htmlSum), "First HTML para") || strings.Contains(string(htmlSum), "Second HTML para") {
		t.Errorf("unexpected ExtractArticleFirstParagraph for <P>: more=%v sum=%q", htmlMore, string(htmlSum))
	}

	// 8. Verify Quill inline image (data:image/png;base64,...) is extracted to images/4/inline_1.png and rewritten in HTML
	inlinePNG := []byte("INLINE_QUILL_IMAGE_BYTES_777")
	inlineB64 := base64.StdEncoding.EncodeToString(inlinePNG)
	quillImgForm := url.Values{
		"flavor":  {"article"},
		"title":   {"Illustrated Article"},
		"format":  {"html"},
		"content": {`<p>Here is an inline photo: <img src="data:image/png;base64,` + inlineB64 + `"></p>`},
		"public1": {"1"},
		"public2": {"1"},
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/@yak.net/post", strings.NewReader(quillImgForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("spock", "secret")
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST Quill inline image article failed: err=%v status=%v", err, resp)
	}
	resp.Body.Close()

	// Check that articles/4.json has src="/images/4/inline_1.png" and NOT base64 data
	art4JSON, err := os.ReadFile(filepath.Join(siteDir, DirArticles, "4.json"))
	if err != nil {
		t.Fatalf("failed to read articles/4.json: %v", err)
	}
	if !strings.Contains(string(art4JSON), `/images/4/inline_1.png`) || strings.Contains(string(art4JSON), "data:image") {
		t.Errorf("expected articles/4.json to reference /images/4/inline_1.png without data URI, got:\n%s", string(art4JSON))
	}

	// Check that /@yak.net/images/4/inline_1.png serves the decoded image bytes
	inlineResp, err := client.Get(baseURL + "/@yak.net/images/4/inline_1.png")
	if err != nil {
		t.Fatalf("GET /@yak.net/images/4/inline_1.png failed: %v", err)
	}
	inlineServed, _ := io.ReadAll(inlineResp.Body)
	inlineResp.Body.Close()
	if inlineResp.StatusCode != http.StatusOK || !bytes.Equal(inlineServed, inlinePNG) {
		t.Errorf("unexpected inline image response: status=%d body=%q", inlineResp.StatusCode, string(inlineServed))
	}

	// Check that /@yak.net/4 renders src="/@yak.net/images/4/inline_1.png"
	perm4Resp, err := client.Get(baseURL + "/@yak.net/4")
	if err != nil {
		t.Fatalf("GET /@yak.net/4 failed: %v", err)
	}
	perm4Bytes, _ := io.ReadAll(perm4Resp.Body)
	perm4Resp.Body.Close()
	if !strings.Contains(string(perm4Bytes), `src="/@yak.net/images/4/inline_1.png"`) {
		t.Errorf("expected /@yak.net/4 to render src=\"/@yak.net/images/4/inline_1.png\", got:\n%s", string(perm4Bytes))
	}

	// 9. Edit article #4 to make it PRIVATE, and verify /@yak.net/images/4/inline_1.png is blocked for anon and kirk, but allowed for spock
	makePrivForm := url.Values{
		"edit_id": {"4"},
		"flavor":  {"article"},
		"title":   {"Illustrated Article (Classified)"},
		"format":  {"html"},
		"content": {`<p>Here is an inline photo: <img src="/@yak.net/images/4/inline_1.png"></p>`},
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/@yak.net/post", strings.NewReader(makePrivForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("spock", "secret")
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST edit article #4 to private failed: err=%v status=%v", err, resp)
	}
	resp.Body.Close()

	// Anonymous user trying to guess /@yak.net/images/4/inline_1.png must get 404
	anonImgResp, err := client.Get(baseURL + "/@yak.net/images/4/inline_1.png")
	if err != nil {
		t.Fatalf("GET private image as anon failed: %v", err)
	}
	anonImgResp.Body.Close()
	if anonImgResp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for anonymous access to private post image, got %d", anonImgResp.StatusCode)
	}

	// Another user (kirk) trying to access spock's private post image must get 404
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/@yak.net/images/4/inline_1.png", nil)
	req.SetBasicAuth("kirk", "secret")
	kirkImgResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET private image as kirk failed: %v", err)
	}
	kirkImgResp.Body.Close()
	if kirkImgResp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for kirk accessing spock's private post image, got %d", kirkImgResp.StatusCode)
	}

	// Author (spock) can still access their own private post image
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/@yak.net/images/4/inline_1.png", nil)
	req.SetBasicAuth("spock", "secret")
	spockImgResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET private image as spock failed: %v", err)
	}
	spockImgResp.Body.Close()
	if spockImgResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for author spock accessing own private post image, got %d", spockImgResp.StatusCode)
	}
}

