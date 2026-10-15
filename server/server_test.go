package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
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
	srv := &Server{
		cfg: Config{
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
			auth, ok := srv.authenticate(req)
			if ok != tc.wantAuth {
				t.Fatalf("authenticate() ok = %v, want %v", ok, tc.wantAuth)
			}
			if tc.wantAuth {
				if auth.IsCrypto != tc.wantCrypto {
					t.Errorf("auth.IsCrypto = %v, want %v", auth.IsCrypto, tc.wantCrypto)
				}
				if !tc.wantCrypto && auth.EffectiveUser != tc.wantUser {
					t.Errorf("auth.EffectiveUser = %s, want %s", auth.EffectiveUser, tc.wantUser)
				}
				if tc.wantCrypto {
					expectedCrypto, _ := DeriveCryptoIdentity(srv.cfg.Salt, tc.username, tc.password)
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
	cfg := Config{
		Addr:     "127.0.0.1:0", // random available port
		Password: sharedPW,
		Salt:     testSalt,
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
	recentRaw := srv.Store().GetRecent(expectedCryptoUser, 10)
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
	cfg := Config{
		HTTPSAddr: "127.0.0.1:0",
		HTTPAddr:  "127.0.0.1:0",
		Password:  sharedPW,
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
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	defer os.RemoveAll(testDir)

	const testSalt = "federation-salt"
	kirkPW := "kobayashi"
	kirkHash := HashPassword(testSalt, kirkPW)

	pwFilePath := filepath.Join(testDir, "users.jsonl")
	jsonlContent := strings.Join([]string{
		`{"handle": "Spock_01", "display": "Spock 🖖", "pw": "llap"}`,
		`{"handle": "Kirk", "pwhash": "` + kirkHash + `"}`,
		"",
	}, "\n")
	if err := os.WriteFile(pwFilePath, []byte(jsonlContent), 0600); err != nil {
		t.Fatalf("failed to write pwfile: %v", err)
	}

	// Note: Password (--pw) is empty, so shared password logins are disabled
	srv, err := New(Config{
		HTTPAddr: "127.0.0.1:0",
		PWFile:   pwFilePath,
		Salt:     testSalt,
		DataFile: "",
	})
	if err != nil {
		t.Fatalf("New() with valid pwfile failed: %v", err)
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
			name:     "unknown user rejected when --pw is empty",
			username: "mccoy",
			password: "llap",
			wantAuth: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)
			req.SetBasicAuth(tc.username, tc.password)
			auth, ok := srv.authenticate(req)
			if ok != tc.wantAuth {
				t.Fatalf("authenticate() ok = %v, want %v", ok, tc.wantAuth)
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

	// Verify invalid handle in pwfile is rejected on load
	badPWFile := filepath.Join(testDir, "bad_users.jsonl")
	if err := os.WriteFile(badPWFile, []byte(`{"handle": "bad-handle!", "pw": "secret"}`+"\n"), 0600); err != nil {
		t.Fatalf("failed to write bad pwfile: %v", err)
	}
	if _, err := New(Config{HTTPAddr: "127.0.0.1:0", PWFile: badPWFile}); err == nil {
		t.Errorf("expected error loading pwfile with invalid handle 'bad-handle!', got nil")
	}
}


