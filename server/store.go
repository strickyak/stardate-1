package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	FlavorLog     = "log"
	FlavorArticle = "article"
	FlavorGallery = "gallery"

	DirMicrologs   = "micrologs"
	DirArticles    = "articles"
	DirGalleries   = "galleries"
	DirImages      = "images"
	DirAttachments = "attachments"
)

// NormalizeFlavor normalizes a posting flavor to "log", "article", or "gallery".
func NormalizeFlavor(flavor string) string {
	switch strings.ToLower(strings.TrimSpace(flavor)) {
	case FlavorArticle:
		return FlavorArticle
	case FlavorGallery:
		return FlavorGallery
	default:
		return FlavorLog
	}
}

// FlavorSubdir returns the per-site subdirectory name ("micrologs", "articles", or "galleries")
// for the given posting flavor.
func FlavorSubdir(flavor string) string {
	switch NormalizeFlavor(flavor) {
	case FlavorArticle:
		return DirArticles
	case FlavorGallery:
		return DirGalleries
	default:
		return DirMicrologs
	}
}

// Message represents a micro-blog log post, article page, or image gallery.
// If is_public is missing in JSON, Go defaults IsPublic to false (private).
type Message struct {
	ID          int64     `json:"id"`
	Flavor      string    `json:"flavor"`                // "log" (default), "article", or "gallery"
	Title       string    `json:"title,omitempty"`       // Used for "article" and "gallery"
	Images      []string  `json:"images,omitempty"`      // Image filenames in images/<id>/
	Attachments []string  `json:"attachments,omitempty"` // Attachment filenames in attachments/<id>/
	IsStarred   bool      `json:"is_starred"`            // Articles and Galleries may be starred
	Author      string    `json:"author"`
	Content     string    `json:"content"`
	HasMore     bool      `json:"-"`                // True in RAM when an article has additional paragraphs on disk
	Format      string    `json:"format,omitempty"` // "text" (default), "markdown", or "html"
	IsPublic    bool      `json:"is_public"`
	Hidden      bool      `json:"hidden,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	Stardate    float64   `json:"stardate"`
}

// toRAMMessage prepares a Message for in-RAM storage.
// Full articles are not kept in RAM; only their first paragraph is retained in RAM.
func toRAMMessage(m Message) Message {
	m.Flavor = NormalizeFlavor(m.Flavor)
	if m.Flavor == FlavorLog {
		m.IsStarred = false
	}
	if m.Flavor == FlavorArticle {
		firstPara, hasMore := SplitFirstParagraphRaw(m.Content, m.Format)
		m.Content = firstPara
		m.HasMore = hasMore
	}
	return m
}

// Store manages thread-safe message persistence and in-RAM state for a site.
// On disk, each post is stored in <siteDir>/<micrologs|articles|galleries>/<id>.json.
// In RAM, full articles are not kept; only their first paragraph is stored.
type Store struct {
	mu       sync.RWMutex
	siteDir  string
	messages []Message
	memFull  map[int64]Message // Used only when siteDir == "" (in-memory mode)
	nextID   int64
}

// NewStore initializes a message store for the given siteDir.
// At startup, it reads all JSON files in <siteDir>/micrologs, <siteDir>/articles,
// and <siteDir>/galleries to assemble the in-RAM state. If siteDir is empty, the store remains in-memory.
func NewStore(siteDir string) (*Store, error) {
	s := &Store{
		siteDir:  siteDir,
		messages: make([]Message, 0),
		memFull:  make(map[int64]Message),
		nextID:   1,
	}

	if siteDir != "" {
		if err := s.load(); err != nil {
			return nil, fmt.Errorf("failed to load messages from %s: %w", siteDir, err)
		}
	}

	return s, nil
}

func (s *Store) postFilePath(flavor string, id int64) string {
	return filepath.Join(s.siteDir, FlavorSubdir(flavor), fmt.Sprintf("%d.json", id))
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	flavorDirs := []struct {
		dir    string
		flavor string
	}{
		{DirMicrologs, FlavorLog},
		{DirArticles, FlavorArticle},
		{DirGalleries, FlavorGallery},
	}

	var loaded []Message
	for _, fd := range flavorDirs {
		dirPath := filepath.Join(s.siteDir, fd.dir)
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			fpath := filepath.Join(dirPath, entry.Name())
			data, err := os.ReadFile(fpath)
			if err != nil {
				return fmt.Errorf("reading %s: %w", fpath, err)
			}
			if len(strings.TrimSpace(string(data))) == 0 {
				continue
			}
			var m Message
			if err := json.Unmarshal(data, &m); err != nil {
				return fmt.Errorf("corrupt post file %s: %w", fpath, err)
			}
			if m.Flavor == "" {
				m.Flavor = fd.flavor
			} else {
				m.Flavor = NormalizeFlavor(m.Flavor)
			}
			if m.ID >= s.nextID {
				s.nextID = m.ID + 1
			}
			loaded = append(loaded, toRAMMessage(m))
		}
	}

	sort.Slice(loaded, func(i, j int) bool {
		return loaded[i].ID < loaded[j].ID
	})
	s.messages = loaded
	return nil
}

func (s *Store) savePostLocked(m Message) error {
	m.Flavor = NormalizeFlavor(m.Flavor)
	if m.Flavor == FlavorLog {
		m.IsStarred = false
	}
	if s.siteDir == "" {
		s.memFull[m.ID] = m
		return nil
	}

	targetPath := s.postFilePath(m.Flavor, m.ID)
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := targetPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, targetPath)
}

func (s *Store) readPostFromDiskLocked(id int64, hintFlavor string) (Message, bool) {
	if s.siteDir == "" {
		m, ok := s.memFull[id]
		return m, ok
	}

	candidates := []string{FlavorLog, FlavorArticle, FlavorGallery}
	if hintFlavor != "" {
		norm := NormalizeFlavor(hintFlavor)
		candidates = []string{norm}
		for _, f := range []string{FlavorLog, FlavorArticle, FlavorGallery} {
			if f != norm {
				candidates = append(candidates, f)
			}
		}
	}

	for _, fl := range candidates {
		p := s.postFilePath(fl, id)
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var m Message
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		if m.Flavor == "" {
			m.Flavor = fl
		} else {
			m.Flavor = NormalizeFlavor(m.Flavor)
		}
		if m.Flavor == FlavorLog {
			m.IsStarred = false
		}
		return m, true
	}
	return Message{}, false
}

// Add adds a new plain-text log message to the store and persists it.
func (s *Store) Add(author, content string, isPublic bool) (Message, error) {
	return s.AddWithFormat(author, content, FormatText, isPublic)
}

// AddWithFormat adds a new log message with the specified format ("text", "markdown", or "html")
// to the store and persists it.
func (s *Store) AddWithFormat(author, content, format string, isPublic bool) (Message, error) {
	return s.AddEntry(author, FlavorLog, "", nil, false, content, format, isPublic)
}

// AddEntry adds a new posting with the given flavor ("log", "article", or "gallery"),
// optional title, images, isStarred flag, content, format, and visibility.
func (s *Store) AddEntry(author, flavor, title string, images []string, isStarred bool, content, format string, isPublic bool) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	normFlavor := NormalizeFlavor(flavor)
	if normFlavor == FlavorLog {
		isStarred = false
		title = ""
		images = nil
	} else if normFlavor == FlavorArticle {
		images = nil
	}

	now := time.Now().UTC()
	msg := Message{
		ID:        s.nextID,
		Flavor:    normFlavor,
		Title:     strings.TrimSpace(title),
		Images:    images,
		IsStarred: isStarred,
		Author:    author,
		Content:   content,
		Format:    NormalizeFormat(format),
		IsPublic:  isPublic,
		CreatedAt: now,
		Stardate:  CalculateStardate(now),
	}
	s.nextID++

	if err := s.savePostLocked(msg); err != nil {
		return msg, fmt.Errorf("failed to persist message: %w", err)
	}

	s.messages = append(s.messages, toRAMMessage(msg))
	return msg, nil
}

// SetFiles updates the Images and Attachments lists for an existing post and persists it.
func (s *Store) SetFiles(id int64, images, attachments []string) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.messages {
		if s.messages[i].ID == id {
			fullMsg, ok := s.readPostFromDiskLocked(id, s.messages[i].Flavor)
			if !ok {
				fullMsg = s.messages[i]
			}
			fullMsg.Images = images
			fullMsg.Attachments = attachments
			if err := s.savePostLocked(fullMsg); err != nil {
				return fullMsg, err
			}
			s.messages[i] = toRAMMessage(fullMsg)
			return fullMsg, nil
		}
	}
	return Message{}, ErrNotFound
}

// ErrNotFound and ErrForbidden are returned by Update when a message does not exist
// or when the requesting user is not authorized to edit it.
var (
	ErrNotFound  = fmt.Errorf("message not found")
	ErrForbidden = fmt.Errorf("forbidden: not authorized to edit message")
)

// GetByID returns the full Message with the given ID (reading from disk for persisted stores).
func (s *Store) GetByID(id int64) (Message, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var hint string
	foundInRAM := false
	for _, m := range s.messages {
		if m.ID == id {
			hint = m.Flavor
			foundInRAM = true
			break
		}
	}
	if fullMsg, ok := s.readPostFromDiskLocked(id, hint); ok {
		return fullMsg, true
	}
	if foundInRAM {
		for _, m := range s.messages {
			if m.ID == id {
				return m, true
			}
		}
	}
	return Message{}, false
}

// GetRAMByID returns the in-RAM Message representation for the given ID (where articles only retain their first paragraph).
func (s *Store) GetRAMByID(id int64) (Message, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, m := range s.messages {
		if m.ID == id {
			return m, true
		}
	}
	return Message{}, false
}

// Update modifies an existing message's content, format, and visibility.
func (s *Store) Update(id int64, editor string, isSuperuser bool, content, format string, isPublic bool) (Message, error) {
	orig, ok := s.GetByID(id)
	if !ok {
		return Message{}, ErrNotFound
	}
	return s.UpdateEntry(id, editor, isSuperuser, orig.Flavor, orig.Title, orig.Images, orig.IsStarred, content, format, isPublic)
}

// UpdateEntry modifies an existing message if its ID exists and either:
// - its Author matches editor, or
// - isSuperuser is true and the existing message is public (IsPublic == true).
func (s *Store) UpdateEntry(id int64, editor string, isSuperuser bool, flavor, title string, images []string, isStarred bool, content, format string, isPublic bool) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.messages {
		if s.messages[i].ID == id {
			oldFlavor := s.messages[i].Flavor
			fullMsg, ok := s.readPostFromDiskLocked(id, oldFlavor)
			if !ok {
				fullMsg = s.messages[i]
			}

			isOwner := fullMsg.Author == editor
			if !isOwner && !(isSuperuser && fullMsg.IsPublic) {
				return Message{}, ErrForbidden
			}
			normFlavor := NormalizeFlavor(flavor)
			if normFlavor == FlavorLog {
				isStarred = false
				title = ""
				images = nil
			} else if normFlavor == FlavorArticle {
				images = nil
			}
			fullMsg.Flavor = normFlavor
			fullMsg.Title = strings.TrimSpace(title)
			if images != nil {
				fullMsg.Images = images
			}
			fullMsg.IsStarred = isStarred
			fullMsg.Content = content
			fullMsg.Format = NormalizeFormat(format)
			if isOwner {
				fullMsg.IsPublic = isPublic
			} else {
				fullMsg.IsPublic = true
			}

			if err := s.savePostLocked(fullMsg); err != nil {
				return fullMsg, fmt.Errorf("failed to persist updated message: %w", err)
			}
			if s.siteDir != "" && NormalizeFlavor(oldFlavor) != normFlavor {
				_ = os.Remove(s.postFilePath(oldFlavor, id))
			}

			s.messages[i] = toRAMMessage(fullMsg)
			return fullMsg, nil
		}
	}
	return Message{}, ErrNotFound
}

// SetHidden marks a message as hidden (or unhidden) and persists the change.
func (s *Store) SetHidden(id int64, hidden bool) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.messages {
		if s.messages[i].ID == id {
			fullMsg, ok := s.readPostFromDiskLocked(id, s.messages[i].Flavor)
			if !ok {
				fullMsg = s.messages[i]
			}
			fullMsg.Hidden = hidden
			if err := s.savePostLocked(fullMsg); err != nil {
				return fullMsg, fmt.Errorf("failed to persist hidden state: %w", err)
			}
			s.messages[i] = toRAMMessage(fullMsg)
			return fullMsg, nil
		}
	}
	return Message{}, ErrNotFound
}

// GetRecent returns up to limit non-hidden messages visible to the specified user,
// ordered newest to oldest, using the in-RAM store (where articles only contain their first paragraph).
func (s *Store) GetRecent(viewer string, limit int) []Message {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	results := make([]Message, 0, limit)
	for i := len(s.messages) - 1; i >= 0; i-- {
		m := s.messages[i]
		if m.Hidden {
			continue
		}
		if m.IsPublic || (viewer != "" && m.Author == viewer) {
			results = append(results, m)
			if len(results) >= limit {
				break
			}
		}
	}

	return results
}

// Count returns the total number of messages in the store.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.messages)
}
