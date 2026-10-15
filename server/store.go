package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Message represents a micro-blog post or note.
// If is_public is missing in JSON, Go defaults IsPublic to false (private).
type Message struct {
	ID        int64     `json:"id"`
	Author    string    `json:"author"`
	Content   string    `json:"content"`
	Format    string    `json:"format,omitempty"` // "text" (default), "markdown", or "html"
	IsPublic  bool      `json:"is_public"`
	CreatedAt time.Time `json:"created_at"`
	Stardate  float64   `json:"stardate"`
}

// Store manages thread-safe message persistence and retrieval.
type Store struct {
	mu       sync.RWMutex
	filePath string
	messages []Message
	nextID   int64
}

// NewStore initializes a message store. If filePath is provided, it loads existing
// messages from disk and persists updates. If filePath is empty, the store remains in-memory.
func NewStore(filePath string) (*Store, error) {
	s := &Store{
		filePath: filePath,
		messages: make([]Message, 0),
		nextID:   1,
	}

	if filePath != "" {
		if err := s.load(); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load messages from %s: %w", filePath, err)
		}
	}

	return s, nil
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}

	var msgs []Message
	if err := json.Unmarshal(data, &msgs); err != nil {
		return fmt.Errorf("corrupt message store: %w", err)
	}

	s.messages = msgs
	for _, m := range msgs {
		if m.ID >= s.nextID {
			s.nextID = m.ID + 1
		}
	}
	return nil
}

func (s *Store) saveLocked() error {
	if s.filePath == "" {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(s.filePath), 0755); err != nil && filepath.Dir(s.filePath) != "." {
		return err
	}

	data, err := json.MarshalIndent(s.messages, "", "  ")
	if err != nil {
		return err
	}

	// Write atomically via a temporary file in the same directory
	tmpPath := s.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.filePath)
}

// Add adds a new plain-text message to the store and persists it if a file path is configured.
func (s *Store) Add(author, content string, isPublic bool) (Message, error) {
	return s.AddWithFormat(author, content, FormatText, isPublic)
}

// AddWithFormat adds a new message with the specified format ("text", "markdown", or "html")
// to the store and persists it if a file path is configured.
func (s *Store) AddWithFormat(author, content, format string, isPublic bool) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	msg := Message{
		ID:        s.nextID,
		Author:    author,
		Content:   content,
		Format:    NormalizeFormat(format),
		IsPublic:  isPublic,
		CreatedAt: now,
		Stardate:  CalculateStardate(now),
	}
	s.nextID++

	s.messages = append(s.messages, msg)

	if err := s.saveLocked(); err != nil {
		return msg, fmt.Errorf("failed to persist message: %w", err)
	}

	return msg, nil
}

// ErrNotFound and ErrForbidden are returned by Update when a message does not exist
// or does not belong to the requesting author.
var (
	ErrNotFound  = fmt.Errorf("message not found")
	ErrForbidden = fmt.Errorf("forbidden: not message author")
)

// Update modifies an existing message if its ID exists and its Author matches author.
func (s *Store) Update(id int64, author, content, format string, isPublic bool) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.messages {
		if s.messages[i].ID == id {
			if s.messages[i].Author != author {
				return Message{}, ErrForbidden
			}
			s.messages[i].Content = content
			s.messages[i].Format = NormalizeFormat(format)
			s.messages[i].IsPublic = isPublic
			if err := s.saveLocked(); err != nil {
				return s.messages[i], fmt.Errorf("failed to persist updated message: %w", err)
			}
			return s.messages[i], nil
		}
	}
	return Message{}, ErrNotFound
}

// GetRecent returns up to limit messages visible to the specified user,
// ordered newest to oldest.
// A message is visible if it is public (IsPublic) or if author matches viewer.
func (s *Store) GetRecent(viewer string, limit int) []Message {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	results := make([]Message, 0, limit)
	// Iterate backwards from the end (newest first)
	for i := len(s.messages) - 1; i >= 0; i-- {
		m := s.messages[i]
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

