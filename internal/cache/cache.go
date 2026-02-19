package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/aaearon/grant-cli/internal/config"
)

// entry is the on-disk envelope for cached data.
type entry[T any] struct {
	CachedAt time.Time `json:"cached_at"`
	Response T         `json:"response"`
}

// Store manages a directory of JSON cache files with TTL expiry.
type Store struct {
	dir string
	ttl time.Duration
	now func() time.Time // injectable clock for testing
}

// NewStore creates a Store with the given directory and TTL.
func NewStore(dir string, ttl time.Duration) *Store {
	return &Store{dir: dir, ttl: ttl, now: time.Now}
}

// Get reads a cached value for key into dst. Returns true on hit, false on miss/expiry/error.
func Get[T any](s *Store, key string, dst *T) bool {
	data, err := os.ReadFile(filepath.Join(s.dir, key+".json"))
	if err != nil {
		return false
	}

	var e entry[T]
	if err := json.Unmarshal(data, &e); err != nil {
		return false
	}

	if s.now().Sub(e.CachedAt) > s.ttl {
		return false
	}

	*dst = e.Response
	return true
}

// Set writes a value to the cache under key. Creates the directory if needed.
func Set[T any](s *Store, key string, value T) error {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}

	e := entry[T]{
		CachedAt: s.now(),
		Response: value,
	}

	data, err := json.Marshal(e)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(s.dir, key+".json"), data, 0600)
}

// Invalidate removes a cached entry by key.
func Invalidate(s *Store, key string) {
	_ = os.Remove(filepath.Join(s.dir, key+".json"))
}

// CacheDir returns the default cache directory path (~/.grant/cache/).
func CacheDir() (string, error) {
	cfgDir, err := config.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfgDir, "cache"), nil
}
