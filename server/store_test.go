package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreVisibilityAndLimit(t *testing.T) {
	store, err := NewStore("")
	if err != nil {
		t.Fatalf("failed to create in-memory store: %v", err)
	}

	// Add 60 public messages from Alice
	for i := 1; i <= 60; i++ {
		_, err := store.Add("alice", fmt.Sprintf("Alice public %d", i), true)
		if err != nil {
			t.Fatalf("failed to add message: %v", err)
		}
	}

	// Add 30 private messages from Alice
	for i := 1; i <= 30; i++ {
		_, err := store.Add("alice", fmt.Sprintf("Alice private %d", i), false)
		if err != nil {
			t.Fatalf("failed to add message: %v", err)
		}
	}

	// Add 30 private messages from Bob
	for i := 1; i <= 30; i++ {
		_, err := store.Add("bob", fmt.Sprintf("Bob private %d", i), false)
		if err != nil {
			t.Fatalf("failed to add message: %v", err)
		}
	}

	// Add 30 public messages from Bob
	for i := 1; i <= 30; i++ {
		_, err := store.Add("bob", fmt.Sprintf("Bob public %d", i), true)
		if err != nil {
			t.Fatalf("failed to add message: %v", err)
		}
	}

	// Total messages in store: 60 + 30 + 30 + 30 = 150
	if total := store.Count(); total != 150 {
		t.Fatalf("expected 150 messages, got %d", total)
	}

	// Anonymous visitor:
	// Public messages: 60 from Alice + 30 from Bob = 90 public messages
	anonMsgs := store.GetRecent("", 100)
	if len(anonMsgs) != 90 {
		t.Errorf("expected anonymous to see 90 public messages, got %d", len(anonMsgs))
	}
	for _, m := range anonMsgs {
		if !m.IsPublic {
			t.Errorf("anonymous user should not see private message: %+v", m)
		}
	}

	// Alice:
	// Visible to Alice: 90 public messages + 30 private messages from Alice = 120 messages.
	// Since limit is 100, Alice should receive exactly 100 most recent visible messages.
	aliceMsgs := store.GetRecent("alice", 100)
	if len(aliceMsgs) != 100 {
		t.Errorf("expected Alice to see 100 messages (limit 100 out of 120 visible), got %d", len(aliceMsgs))
	}
	for _, m := range aliceMsgs {
		if !m.IsPublic && m.Author != "alice" {
			t.Errorf("Alice should not see private messages by others: %+v", m)
		}
	}

	// Bob:
	// Visible to Bob: 90 public messages + 30 private messages from Bob = 120 messages.
	// Bob should receive 100 most recent.
	bobMsgs := store.GetRecent("bob", 100)
	if len(bobMsgs) != 100 {
		t.Errorf("expected Bob to see 100 messages, got %d", len(bobMsgs))
	}
	for _, m := range bobMsgs {
		if !m.IsPublic && m.Author != "bob" {
			t.Errorf("Bob should not see private messages by others: %+v", m)
		}
	}

	// Charlie (logged in, has 0 private notes):
	// Sees only public messages (90)
	charlieMsgs := store.GetRecent("charlie", 100)
	if len(charlieMsgs) != 90 {
		t.Errorf("expected Charlie to see 90 public messages, got %d", len(charlieMsgs))
	}
}

func TestStorePersistence(t *testing.T) {
	testDir := filepath.Join(".", ".test_tmp")
	_ = os.RemoveAll(testDir)
	defer os.RemoveAll(testDir)

	dbFile := filepath.Join(testDir, "messages.json")

	store1, err := NewStore(dbFile)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	m1, err := store1.Add("spock", "Fascinating.", true)
	if err != nil {
		t.Fatalf("failed to add message: %v", err)
	}
	m2, err := store1.Add("kirk", "Personal log: private entry", false)
	if err != nil {
		t.Fatalf("failed to add message: %v", err)
	}

	// Reload from same file
	store2, err := NewStore(dbFile)
	if err != nil {
		t.Fatalf("failed to reload store: %v", err)
	}

	if store2.Count() != 2 {
		t.Fatalf("expected 2 messages reloaded, got %d", store2.Count())
	}

	spockMsgs := store2.GetRecent("spock", 10)
	if len(spockMsgs) != 1 || spockMsgs[0].Content != m1.Content {
		t.Errorf("unexpected messages for spock: %+v", spockMsgs)
	}

	kirkMsgs := store2.GetRecent("kirk", 10)
	if len(kirkMsgs) != 2 {
		t.Errorf("expected 2 messages for kirk, got %d", len(kirkMsgs))
	}
	if kirkMsgs[0].Content != m2.Content { // newest first
		t.Errorf("expected newest message to be Kirk's, got %s", kirkMsgs[0].Content)
	}

	// Test missing is_public field in JSON defaults to private (not public)
	missingFieldFile := filepath.Join(testDir, "missing_is_public.json")
	rawJSON := `[
  {
    "id": 1,
    "author": "mccoy",
    "content": "I'm a doctor, not a bricklayer!",
    "created_at": "2026-10-15T07:00:00Z",
    "stardate": 26780.0
  }
]`
	if err := os.WriteFile(missingFieldFile, []byte(rawJSON), 0644); err != nil {
		t.Fatalf("failed to write raw JSON: %v", err)
	}

	store3, err := NewStore(missingFieldFile)
	if err != nil {
		t.Fatalf("failed to load store with missing is_public: %v", err)
	}
	if anon := store3.GetRecent("", 10); len(anon) != 0 {
		t.Errorf("expected 0 public messages when is_public is missing in JSON, got %d", len(anon))
	}
	if mccoy := store3.GetRecent("mccoy", 10); len(mccoy) != 1 || mccoy[0].IsPublic {
		t.Errorf("expected message with missing is_public to be private for mccoy, got %+v", mccoy)
	}
}
