package server

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
	"regexp"
	"strings"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"
)

//go:embed assets/quill.js assets/quill.snow.css
var staticAssets embed.FS

// Format constants for Message.Format.
const (
	FormatText     = "text"
	FormatMarkdown = "markdown"
	FormatHTML     = "html"
)

var (
	mdRenderer goldmark.Markdown
	htmlPolicy *bluemonday.Policy
	quillClass = regexp.MustCompile(`^ql-[a-zA-Z0-9_-]+$`)
)

func init() {
	mdRenderer = goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithRendererOptions(
			html.WithHardWraps(),
			html.WithUnsafe(), // Output is always sanitized by bluemonday below
		),
	)

	p := bluemonday.UGCPolicy()
	p.AllowAttrs("class").Matching(quillClass).Globally()
	p.AllowAttrs("data-language", "spellcheck").OnElements("pre", "div")
	p.AllowAttrs("target", "rel").OnElements("a")
	htmlPolicy = p
}

// NormalizeFormat returns a canonical format string ("text", "markdown", or "html").
func NormalizeFormat(f string) string {
	switch strings.ToLower(strings.TrimSpace(f)) {
	case FormatMarkdown, "md":
		return FormatMarkdown
	case FormatHTML, "quill", "richtext":
		return FormatHTML
	default:
		return FormatText
	}
}

// RenderAndSanitize converts message content in the given format ("text", "markdown", "html")
// into safe, sanitized HTML suitable for rendering in a browser.
func RenderAndSanitize(content, format string) template.HTML {
	switch NormalizeFormat(format) {
	case FormatMarkdown:
		var buf bytes.Buffer
		if err := mdRenderer.Convert([]byte(content), &buf); err != nil {
			escaped := template.HTMLEscapeString(content)
			return template.HTML(`<div class="plain-text">` + escaped + `</div>`)
		}
		sanitized := htmlPolicy.SanitizeBytes(buf.Bytes())
		return template.HTML(`<div class="rich-content">` + string(sanitized) + `</div>`)

	case FormatHTML:
		sanitized := htmlPolicy.Sanitize(content)
		return template.HTML(`<div class="rich-content">` + sanitized + `</div>`)

	default:
		escaped := template.HTMLEscapeString(content)
		return template.HTML(`<div class="plain-text">` + escaped + `</div>`)
	}
}

func (s *Server) handleStaticQuillJS(w http.ResponseWriter, r *http.Request) {
	data, err := staticAssets.ReadFile("assets/quill.js")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleStaticQuillCSS(w http.ResponseWriter, r *http.Request) {
	data, err := staticAssets.ReadFile("assets/quill.snow.css")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
