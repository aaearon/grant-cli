package k8s

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

func testKey() CredentialKey {
	return CredentialKey{CSP: "AWS", FQDN: "prod.eks.example", RoleID: "arn:role/admin"}
}

func credWithExpiry(t time.Time) *k8smodels.IdsecSCAK8sExecCredential {
	return &k8smodels.IdsecSCAK8sExecCredential{
		APIVersion: "client.authentication.k8s.io/v1beta1",
		Kind:       "ExecCredential",
		Status: k8smodels.IdsecSCAK8sExecCredentialStatus{
			Token:               "tok",
			ExpirationTimestamp: t.UTC().Format(time.RFC3339),
		},
	}
}

func TestCredentialCacheRoundTrip(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	c := NewCredentialCache(t.TempDir())
	c.now = func() time.Time { return now }

	cred := credWithExpiry(now.Add(10 * time.Minute))
	if err := c.Put(testKey(), cred); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok := c.Get(testKey())
	if !ok {
		t.Fatal("expected a cache hit")
	}
	if got.Status.Token != "tok" {
		t.Errorf("token = %q", got.Status.Token)
	}
	if got.Status.ExpirationTimestamp != cred.Status.ExpirationTimestamp {
		t.Errorf("expirationTimestamp changed on the round trip: %q -> %q",
			cred.Status.ExpirationTimestamp, got.Status.ExpirationTimestamp)
	}
}

// The SDK bakes its early-refresh buffer into expirationTimestamp. The cache
// must treat that value as final and never subtract another buffer.
func TestCredentialCacheDoesNotReapplyBuffer(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	c := NewCredentialCache(t.TempDir())
	c.now = func() time.Time { return now }

	expiry := now.Add(30 * time.Second)
	if err := c.Put(testKey(), credWithExpiry(expiry)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// 30s before the stamped expiry the credential is still valid, even though a
	// naive second application of a 60s buffer would have expired it.
	if _, ok := c.Get(testKey()); !ok {
		t.Fatal("credential expired early — the refresh buffer was applied twice")
	}
}

func TestCredentialCacheExpiry(t *testing.T) {
	base := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		expiry  time.Time
		readAt  time.Time
		wantHit bool
	}{
		{name: "valid", expiry: base.Add(time.Hour), readAt: base, wantHit: true},
		{name: "exactly at expiry is a miss", expiry: base, readAt: base, wantHit: false},
		{name: "past expiry", expiry: base.Add(-time.Second), readAt: base, wantHit: false},
		{
			name:    "expiry implausibly far ahead (clock skew) is a miss",
			expiry:  base.Add(maxCredentialLifetime + time.Hour),
			readAt:  base,
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCredentialCache(t.TempDir())
			c.now = func() time.Time { return tt.readAt }
			if err := c.Put(testKey(), credWithExpiry(tt.expiry)); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if _, ok := c.Get(testKey()); ok != tt.wantHit {
				t.Errorf("hit = %v, want %v", ok, tt.wantHit)
			}
		})
	}
}

func TestCredentialCacheRejectsUncacheableCredentials(t *testing.T) {
	tests := []struct {
		name string
		cred *k8smodels.IdsecSCAK8sExecCredential
	}{
		{name: "nil", cred: nil},
		{
			name: "no expirationTimestamp",
			cred: &k8smodels.IdsecSCAK8sExecCredential{Status: k8smodels.IdsecSCAK8sExecCredentialStatus{Token: "t"}},
		},
		{
			name: "malformed expirationTimestamp",
			cred: &k8smodels.IdsecSCAK8sExecCredential{Status: k8smodels.IdsecSCAK8sExecCredentialStatus{
				Token: "t", ExpirationTimestamp: "not-a-time",
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			c := NewCredentialCache(dir)
			if err := c.Put(testKey(), tt.cred); err != nil {
				t.Fatalf("Put should be a silent no-op, got %v", err)
			}
			if _, ok := c.Get(testKey()); ok {
				t.Error("expected a miss: credentials without a usable expiry are not cacheable")
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Errorf("nothing should have been written, found %d files", len(entries))
			}
		})
	}
}

func TestCredentialCacheFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}

	dir := filepath.Join(t.TempDir(), "cache")
	now := time.Now()
	c := NewCredentialCache(dir)

	if err := c.Put(testKey(), credWithExpiry(now.Add(time.Hour))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("cache dir mode = %o, want 0700", di.Mode().Perm())
	}

	path := c.pathFor(testKey())
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("cache file mode = %o, want 0600", fi.Mode().Perm())
	}
}

// A cache file that is readable beyond the owner may have been tampered with or
// observed; it is refused and removed rather than trusted.
func TestCredentialCacheRefusesLooseFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}

	c := NewCredentialCache(t.TempDir())
	if err := c.Put(testKey(), credWithExpiry(time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	path := c.pathFor(testKey())
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, ok := c.Get(testKey()); ok {
		t.Fatal("expected a miss for a world-readable cache file")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the insecure cache file should have been removed")
	}
}

func TestCredentialCacheReusedUntilExpiryThenRefetched(t *testing.T) {
	base := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	current := base

	c := NewCredentialCache(t.TempDir())
	c.now = func() time.Time { return current }

	if err := c.Put(testKey(), credWithExpiry(base.Add(5*time.Minute))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	current = base.Add(4 * time.Minute)
	if _, ok := c.Get(testKey()); !ok {
		t.Error("credential should still be reused before its stamped expiry")
	}

	current = base.Add(6 * time.Minute)
	if _, ok := c.Get(testKey()); ok {
		t.Error("credential should be refetched after its stamped expiry")
	}
}

func TestCredentialCacheKeysAreDistinct(t *testing.T) {
	c := NewCredentialCache(t.TempDir())
	keys := []CredentialKey{
		{CSP: "AWS", FQDN: "a", RoleID: "r"},
		{CSP: "AZURE", FQDN: "a", RoleID: "r"},
		{CSP: "AWS", FQDN: "b", RoleID: "r"},
		{CSP: "AWS", FQDN: "a", RoleID: "r2"},
		{CSP: "AWS", FQDN: "a", RoleID: "r", Namespace: "ns"},
	}

	seen := map[string]bool{}
	for _, k := range keys {
		path := c.pathFor(k)
		if seen[path] {
			t.Errorf("cache key collision for %+v", k)
		}
		seen[path] = true
	}
}

func TestCredentialCacheMissOnUnwritableDir(t *testing.T) {
	c := NewCredentialCache(t.TempDir())
	if _, ok := c.Get(testKey()); ok {
		t.Error("expected a miss on an empty cache")
	}
}
