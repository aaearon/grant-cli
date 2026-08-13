//go:build windows

package k8s

import (
	"testing"
	"time"
)

// TestCredentialCacheRoundTripOnWindows guards a regression that made the cache
// permanently unusable on Windows.
//
// Go synthesizes FileMode permission bits on Windows from a single read-only
// attribute: every ordinary file reports 0666 and every directory 0777
// (os/types_windows.go). A POSIX `perm&0o077 != 0` check therefore rejects
// everything, so every Get missed and kubectl re-authenticated on every single
// call. The permission and ownership checks are now gated behind
// posixPermissions.
func TestCredentialCacheRoundTripOnWindows(t *testing.T) {
	if posixPermissions {
		t.Fatal("posixPermissions must be false on Windows")
	}

	c := NewCredentialCache(t.TempDir())
	key := testKey()

	if err := c.Put(key, credWithExpiry(time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	cred, ok := c.Get(key)
	if !ok {
		t.Fatal("cache miss on Windows: the credential cache is unusable and kubectl will re-authenticate every call")
	}
	if cred.Status.Token != "tok" {
		t.Errorf("token = %q", cred.Status.Token)
	}
}
