package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGet_Miss(t *testing.T) {
	t.Parallel()
	s := NewStore(t.TempDir(), 4*time.Hour)

	var out []string
	ok := Get(s, "nonexistent", &out)
	if ok {
		t.Fatal("expected miss for nonexistent key")
	}
}

func TestSetAndGet_RoundTrip(t *testing.T) {
	t.Parallel()
	s := NewStore(t.TempDir(), 4*time.Hour)

	in := []string{"alpha", "beta"}
	if err := Set(s, "items", in); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	var out []string
	ok := Get(s, "items", &out)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(out) != 2 || out[0] != "alpha" || out[1] != "beta" {
		t.Errorf("got %v, want [alpha beta]", out)
	}
}

func TestGet_Expired(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ttl := 1 * time.Hour

	// Write with a clock in the past
	past := time.Now().Add(-2 * time.Hour)
	s := &Store{dir: dir, ttl: ttl, now: func() time.Time { return past }}
	if err := Set(s, "old", "data"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Read with real clock — entry should be expired
	s2 := NewStore(dir, ttl)
	var out string
	ok := Get(s2, "old", &out)
	if ok {
		t.Fatal("expected miss for expired entry")
	}
}

func TestGet_CorruptJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := NewStore(dir, 4*time.Hour)

	// Write garbage to the cache file
	path := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("failed to write corrupt file: %v", err)
	}

	var out string
	ok := Get(s, "corrupt", &out)
	if ok {
		t.Fatal("expected miss for corrupt JSON")
	}
}

func TestSet_CreatesDirectory(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "nested", "cache")
	s := NewStore(dir, 4*time.Hour)

	if err := Set(s, "key", "value"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "key.json")); os.IsNotExist(err) {
		t.Fatal("expected cache file to be created")
	}
}

func TestSet_FilePermissions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := NewStore(dir, 4*time.Hour)

	if err := Set(s, "perms", "data"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "perms.json"))
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

type testStruct struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func TestRoundTrip_Struct(t *testing.T) {
	t.Parallel()
	s := NewStore(t.TempDir(), 4*time.Hour)

	in := testStruct{Name: "test", Count: 42}
	if err := Set(s, "struct", in); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	var out testStruct
	ok := Get(s, "struct", &out)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if out.Name != "test" || out.Count != 42 {
		t.Errorf("got %+v, want {Name:test Count:42}", out)
	}
}

func TestInvalidate(t *testing.T) {
	t.Parallel()
	s := NewStore(t.TempDir(), 4*time.Hour)

	if err := Set(s, "del-me", "data"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	Invalidate(s, "del-me")

	var out string
	ok := Get(s, "del-me", &out)
	if ok {
		t.Fatal("expected miss after invalidation")
	}
}

func TestInvalidate_NonExistent(t *testing.T) {
	t.Parallel()
	s := NewStore(t.TempDir(), 4*time.Hour)

	// Should not panic
	Invalidate(s, "no-such-key")
}

func TestCacheDir(t *testing.T) {
	dir, err := CacheDir()
	if err != nil {
		t.Fatalf("CacheDir() error = %v", err)
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("expected absolute path, got %q", dir)
	}
	if filepath.Base(dir) != "cache" {
		t.Errorf("expected dir to end with 'cache', got %q", dir)
	}
}
