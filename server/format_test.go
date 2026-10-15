package server

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRenderAndSanitize(t *testing.T) {
	// 1. Plain text escapes all HTML
	plainOut := string(RenderAndSanitize("Hello <b>world</b> & <script>alert(1)</script>", FormatText))
	if strings.Contains(plainOut, "<script>") || strings.Contains(plainOut, "<b>") {
		t.Errorf("expected plain text to escape HTML tags, got: %s", plainOut)
	}
	if !strings.Contains(plainOut, "&lt;b&gt;world&lt;/b&gt;") {
		t.Errorf("expected escaped <b> tag in plain text output, got: %s", plainOut)
	}

	// 2. Markdown renders formatting and strips XSS
	mdSrc := "# Starfleet Briefing\n\nThis is **bold** and *italic* with a [safe link](https://example.com) and [xss](javascript:alert(1)) plus <script>evil()</script>."
	mdOut := string(RenderAndSanitize(mdSrc, FormatMarkdown))
	if !strings.Contains(mdOut, "<h1>Starfleet Briefing</h1>") {
		t.Errorf("expected <h1> in markdown output, got: %s", mdOut)
	}
	if !strings.Contains(mdOut, "<strong>bold</strong>") || !strings.Contains(mdOut, "<em>italic</em>") {
		t.Errorf("expected bold and italic tags in markdown output, got: %s", mdOut)
	}
	if strings.Contains(mdOut, "<script>") || strings.Contains(mdOut, "javascript:") {
		t.Errorf("expected XSS payloads to be stripped from markdown output, got: %s", mdOut)
	}

	// 3. HTML (Quill) preserves rich formatting and strips XSS
	htmlSrc := `<p class="ql-align-center">Captain's <strong>Rich</strong> <em>Log</em></p><img src="x" onerror="alert(1)"><script>steal()</script>`
	htmlOut := string(RenderAndSanitize(htmlSrc, FormatHTML))
	if !strings.Contains(htmlOut, `class="ql-align-center"`) || !strings.Contains(htmlOut, `<strong>Rich</strong> <em>Log</em>`) {
		t.Errorf("expected safe Quill HTML to be preserved, got: %s", htmlOut)
	}
	if strings.Contains(htmlOut, "onerror") || strings.Contains(htmlOut, "<script>") {
		t.Errorf("expected XSS attributes and script tags to be stripped from HTML output, got: %s", htmlOut)
	}
}

func TestServerMarkdownAndQuillIntegration(t *testing.T) {
	const sharedPW = "quill-test-pw"
	srv, err := New(Config{
		HTTPAddr: "127.0.0.1:0",
		Password: sharedPW,
		Salt:     "quill-salt",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
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

	// 1. Verify embedded Quill JS & CSS static endpoints
	for _, path := range []string{"/static/quill.js", "/static/quill.snow.css"} {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			t.Fatalf("GET %s failed: %v", path, err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || len(data) < 1000 {
			t.Errorf("expected 200 OK and non-empty asset for %s, got status %d len %d", path, resp.StatusCode, len(data))
		}
	}

	// 2. Post a public Markdown message containing formatting and an XSS attempt
	mdForm := url.Values{
		"format":  {"markdown"},
		"content": {"**Warp Core** status: *nominal* <script>alert('xss')</script>"},
		"public1": {"1"},
		"public2": {"1"},
	}
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/post", strings.NewReader(mdForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("geordi", sharedPW)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST markdown failed: %v", err)
	}
	resp.Body.Close()

	// 3. Post an encrypted private Quill HTML message as a crypto user
	cryptoPass := sharedPW + "/data_positronic_net"
	htmlForm := url.Values{
		"format":  {"html"},
		"content": {"<p>Positronic <u>subroutine</u> <strong>alpha</strong></p><script>bad()</script>"},
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/post", strings.NewReader(htmlForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("data", cryptoPass)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("POST html failed: %v", err)
	}
	resp.Body.Close()

	// 4. Fetch root page as crypto user "data" and verify rendered & sanitized output
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/", nil)
	req.SetBasicAuth("data", cryptoPass)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	pageHTML := string(bodyBytes)

	if !strings.Contains(pageHTML, "<strong>Warp Core</strong> status: <em>nominal</em>") {
		t.Errorf("expected rendered Markdown HTML on page, got:\n%s", pageHTML)
	}
	if !strings.Contains(pageHTML, "<p>Positronic <u>subroutine</u> <strong>alpha</strong></p>") {
		t.Errorf("expected decrypted and sanitized Quill HTML on page, got:\n%s", pageHTML)
	}
	if strings.Contains(pageHTML, "alert('xss')") || strings.Contains(pageHTML, "bad()") {
		t.Errorf("XSS script content must not appear in rendered page!")
	}

	// 5. Verify EDIT button visibility:
	// "data" should see EDIT for message #2 (their own), but NOT for message #1 (authored by "geordi")
	if !strings.Contains(pageHTML, `data-id="2"`) || !strings.Contains(pageHTML, `onclick="startEdit(this)">EDIT</button>`) {
		t.Errorf("expected EDIT button for user's own post (id=2)")
	}
	if strings.Contains(pageHTML, `data-id="1"`) {
		t.Errorf("user 'data' must not see EDIT button for geordi's post (id=1)")
	}

	// 6. Attempt by "data" to edit geordi's post (id=1) must return 403 Forbidden
	forbidForm := url.Values{
		"edit_id": {"1"},
		"format":  {"text"},
		"content": {"hacked by lore"},
		"public1": {"1"},
		"public2": {"1"},
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/post", strings.NewReader(forbidForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("data", cryptoPass)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("POST edit forbidden test failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden when editing another user's post, got %d", resp.StatusCode)
	}

	// 7. "geordi" edits his own post (id=1)
	editForm := url.Values{
		"edit_id": {"1"},
		"format":  {"markdown"},
		"content": {"**Warp Core** status: *upgraded to 110%*"},
		"public1": {"1"},
		"public2": {"1"},
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/post", strings.NewReader(editForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("geordi", sharedPW)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("POST edit own post failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected 303 See Other after editing own post, got %d", resp.StatusCode)
	}

	// Verify updated content is rendered on GET /
	resp, err = client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET / after edit failed: %v", err)
	}
	bodyBytes, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(bodyBytes), "<em>upgraded to 110%</em>") {
		t.Errorf("expected edited content to appear on page, got:\n%s", string(bodyBytes))
	}
}

