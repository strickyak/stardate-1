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

	store1, err := NewStore(testDir)
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
	fullArticle := "First paragraph of the treatise.\n\nSecond paragraph that should only live on disk."
	m3, err := store1.AddEntry("spock", FlavorArticle, "Logic Treatise", nil, true, fullArticle, FormatMarkdown, true)
	if err != nil {
		t.Fatalf("failed to add article: %v", err)
	}

	// Verify individual files exist in micrologs/ and articles/
	if _, err := os.Stat(filepath.Join(testDir, DirMicrologs, "1.json")); err != nil {
		t.Errorf("expected micrologs/1.json to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(testDir, DirMicrologs, "2.json")); err != nil {
		t.Errorf("expected micrologs/2.json to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(testDir, DirArticles, "3.json")); err != nil {
		t.Errorf("expected articles/3.json to exist: %v", err)
	}

	// Verify in-RAM article only stores the first paragraph, while GetByID reads full article from disk
	ramM3, ok := store1.GetRAMByID(m3.ID)
	if !ok || ramM3.Content != "First paragraph of the treatise." || !ramM3.HasMore {
		t.Errorf("expected in-RAM article to hold only first paragraph with HasMore=true, got %+v", ramM3)
	}
	diskM3, ok := store1.GetByID(m3.ID)
	if !ok || diskM3.Content != fullArticle {
		t.Errorf("expected GetByID to return full article from disk, got %+v", diskM3)
	}

	// Reload from same site directory
	store2, err := NewStore(testDir)
	if err != nil {
		t.Fatalf("failed to reload store: %v", err)
	}

	if store2.Count() != 3 {
		t.Fatalf("expected 3 messages reloaded, got %d", store2.Count())
	}

	ramM3Reloaded, ok := store2.GetRAMByID(m3.ID)
	if !ok || ramM3Reloaded.Content != "First paragraph of the treatise." || !ramM3Reloaded.HasMore {
		t.Errorf("expected reloaded in-RAM article to hold only first paragraph, got %+v", ramM3Reloaded)
	}
	diskM3Reloaded, ok := store2.GetByID(m3.ID)
	if !ok || diskM3Reloaded.Content != fullArticle {
		t.Errorf("expected reloaded GetByID to return full article from disk, got %+v", diskM3Reloaded)
	}

	spockMsgs := store2.GetRecent("spock", 10)
	if len(spockMsgs) != 2 || spockMsgs[1].Content != m1.Content {
		t.Errorf("unexpected messages for spock: %+v", spockMsgs)
	}

	kirkMsgs := store2.GetRecent("kirk", 10)
	if len(kirkMsgs) != 3 {
		t.Errorf("expected 3 messages for kirk, got %d", len(kirkMsgs))
	}
	if kirkMsgs[1].Content != m2.Content {
		t.Errorf("expected second newest message to be Kirk's, got %s", kirkMsgs[1].Content)
	}

	// Test missing is_public field in JSON defaults to private (not public)
	missingSiteDir := filepath.Join(testDir, "missing_site")
	missingLogDir := filepath.Join(missingSiteDir, DirMicrologs)
	if err := os.MkdirAll(missingLogDir, 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	rawJSON := `{
  "id": 1,
  "author": "mccoy",
  "content": "I'm a doctor, not a bricklayer!",
  "created_at": "2026-10-15T07:00:00Z",
  "stardate": 26780.0
}`
	if err := os.WriteFile(filepath.Join(missingLogDir, "1.json"), []byte(rawJSON), 0644); err != nil {
		t.Fatalf("failed to write raw JSON: %v", err)
	}

	store3, err := NewStore(missingSiteDir)
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
