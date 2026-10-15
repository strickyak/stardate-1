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

var (
	blankLineRe = regexp.MustCompile(`\n[ \t]*\n+`)
	pTagOpenRe  = regexp.MustCompile(`(?i)<p(?:\s[^>]*)?>`)
	pTagCloseRe = regexp.MustCompile(`(?i)</p>`)
	emptyHTMLRe = regexp.MustCompile(`(?i)^(?:\s|<p(?:\s[^>]*)?>\s*(?:<br\s*/?>)?\s*</p>|<br\s*/?>)*$`)
)

// SplitFirstParagraphRaw splits content into its first paragraph (up until a blank line
// or a <p>/<P> boundary after some content) and returns (firstParagraphRaw, hasMore).
func SplitFirstParagraphRaw(content, format string) (string, bool) {
	normFmt := NormalizeFormat(format)
	norm := strings.ReplaceAll(content, "\r\n", "\n")
	norm = strings.TrimSpace(norm)
	if norm == "" {
		return content, false
	}

	if normFmt == FormatHTML {
		// Strip leading empty paragraphs such as <p><br></p> or <p></p>
		for {
			trimmed := strings.TrimSpace(norm)
			lower := strings.ToLower(trimmed)
			if strings.HasPrefix(lower, "<p><br></p>") {
				norm = strings.TrimSpace(trimmed[len("<p><br></p>"):])
				continue
			}
			if strings.HasPrefix(lower, "<p><br/></p>") {
				norm = strings.TrimSpace(trimmed[len("<p><br/></p>"):])
				continue
			}
			if strings.HasPrefix(lower, "<p></p>") {
				norm = strings.TrimSpace(trimmed[len("<p></p>"):])
				continue
			}
			break
		}

		searchStart := 0
		if loc := pTagOpenRe.FindStringIndex(norm); loc != nil && loc[0] == 0 {
			searchStart = loc[1]
		}

		cutIdx := -1
		restStart := -1

		// 1. Check for blank line after some content
		if bloc := blankLineRe.FindStringIndex(norm[searchStart:]); bloc != nil && bloc[0] > 0 {
			cutIdx = searchStart + bloc[0]
			restStart = searchStart + bloc[1]
		}

		// 2. Check for closing </p> if it started with <p>
		if searchStart > 0 {
			if cloc := pTagCloseRe.FindStringIndex(norm[searchStart:]); cloc != nil {
				cEnd := searchStart + cloc[1]
				if cutIdx == -1 || cEnd < cutIdx {
					cutIdx = cEnd
					restStart = cEnd
				}
			}
		}

		// 3. Check for a subsequent <p> or <P> tag after some content
		if ploc := pTagOpenRe.FindStringIndex(norm[searchStart:]); ploc != nil && ploc[0] > 0 {
			pStart := searchStart + ploc[0]
			if cutIdx == -1 || pStart < cutIdx {
				cutIdx = pStart
				restStart = pStart
			}
		}

		if cutIdx != -1 && restStart <= len(norm) {
			firstPart := strings.TrimSpace(norm[:cutIdx])
			restPart := strings.TrimSpace(norm[restStart:])
			if firstPart != "" && !emptyHTMLRe.MatchString(restPart) {
				return firstPart, true
			}
		}
		return content, false
	}

	// Plain text or Markdown: split at the first blank line (or <p>/<P> after some content)
	cutIdx := -1
	restStart := -1

	if bloc := blankLineRe.FindStringIndex(norm); bloc != nil && bloc[0] > 0 {
		cutIdx = bloc[0]
		restStart = bloc[1]
	}
	if ploc := pTagOpenRe.FindStringIndex(norm); ploc != nil && ploc[0] > 0 {
		if cutIdx == -1 || ploc[0] < cutIdx {
			cutIdx = ploc[0]
			restStart = ploc[1]
		}
	}

	if cutIdx != -1 && restStart <= len(norm) {
		firstPart := strings.TrimSpace(norm[:cutIdx])
		restPart := strings.TrimSpace(norm[restStart:])
		if firstPart != "" && restPart != "" {
			return firstPart, true
		}
	}

	return content, false
}

// ExtractArticleFirstParagraph returns the rendered HTML of the first paragraph of content
// (up until a blank line or a <p>/<P> boundary after some content) and a boolean indicating
// whether additional content was truncated.
func ExtractArticleFirstParagraph(content, format string) (template.HTML, bool) {
	normFmt := NormalizeFormat(format)
	firstPart, hasMore := SplitFirstParagraphRaw(content, normFmt)
	return RenderAndSanitize(firstPart, normFmt), hasMore
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
