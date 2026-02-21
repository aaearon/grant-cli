package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecordSession_AndLookup(t *testing.T) {
	t.Parallel()
	s := NewStore(t.TempDir(), 25*time.Hour)
	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)

	if err := RecordSession(s, "sess-1", now); err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	timestamps := SessionTimestamps(s)
	ts, ok := timestamps["sess-1"]
	if !ok {
		t.Fatal("expected sess-1 in timestamps")
	}
	if !ts.Equal(now) {
		t.Errorf("timestamp = %v, want %v", ts, now)
	}
}

func TestSessionTimestamps_Empty(t *testing.T) {
	t.Parallel()
	s := NewStore(t.TempDir(), 25*time.Hour)

	timestamps := SessionTimestamps(s)
	if len(timestamps) != 0 {
		t.Errorf("expected empty map, got %v", timestamps)
	}
}

func TestSessionTimestamps_CorruptFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := NewStore(dir, 25*time.Hour)

	// Write garbage to the cache file
	path := filepath.Join(dir, sessionTimestampsKey+".json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("failed to write corrupt file: %v", err)
	}

	timestamps := SessionTimestamps(s)
	if len(timestamps) != 0 {
		t.Errorf("expected empty map for corrupt file, got %v", timestamps)
	}
}

func TestCleanupSessions(t *testing.T) {
	t.Parallel()
	s := NewStore(t.TempDir(), 25*time.Hour)
	now := time.Now()

	// Record 3 sessions
	for _, id := range []string{"sess-1", "sess-2", "sess-3"} {
		if err := RecordSession(s, id, now); err != nil {
			t.Fatalf("RecordSession(%s) error = %v", id, err)
		}
	}

	// Cleanup with only 2 active
	if err := CleanupSessions(s, []string{"sess-1", "sess-3"}); err != nil {
		t.Fatalf("CleanupSessions() error = %v", err)
	}

	timestamps := SessionTimestamps(s)
	if _, ok := timestamps["sess-1"]; !ok {
		t.Error("expected sess-1 to remain")
	}
	if _, ok := timestamps["sess-3"]; !ok {
		t.Error("expected sess-3 to remain")
	}
	if _, ok := timestamps["sess-2"]; ok {
		t.Error("expected sess-2 to be removed")
	}
}

func TestSessionTimestamps_StaleFiltered(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ttl := 25 * time.Hour

	// Write entry with a clock 26 hours in the past
	past := time.Now().Add(-26 * time.Hour)
	s := &Store{dir: dir, ttl: ttl, now: func() time.Time { return past }}
	if err := RecordSession(s, "old-sess", past); err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	// Read with real clock — the entire cache entry should be expired
	s2 := NewStore(dir, ttl)
	timestamps := SessionTimestamps(s2)
	if _, ok := timestamps["old-sess"]; ok {
		t.Error("expected stale session to be filtered out")
	}
}

func TestRecordSession_Append(t *testing.T) {
	t.Parallel()
	s := NewStore(t.TempDir(), 25*time.Hour)
	now := time.Now()

	if err := RecordSession(s, "sess-1", now); err != nil {
		t.Fatalf("RecordSession(sess-1) error = %v", err)
	}
	if err := RecordSession(s, "sess-2", now.Add(5*time.Minute)); err != nil {
		t.Fatalf("RecordSession(sess-2) error = %v", err)
	}

	timestamps := SessionTimestamps(s)
	if len(timestamps) != 2 {
		t.Errorf("expected 2 entries, got %d", len(timestamps))
	}
	if _, ok := timestamps["sess-1"]; !ok {
		t.Error("expected sess-1 in timestamps")
	}
	if _, ok := timestamps["sess-2"]; !ok {
		t.Error("expected sess-2 in timestamps")
	}
}
