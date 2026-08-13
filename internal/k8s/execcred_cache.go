package k8s

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// maxCredentialLifetime caps how far ahead a cached credential's expiry may sit.
// A value beyond this indicates client/server clock skew (or a tampered file),
// and the credential is not trusted rather than being cached indefinitely.
const maxCredentialLifetime = 24 * time.Hour

// CredentialKey identifies a cached ExecCredential.
type CredentialKey struct {
	CSP       string
	FQDN      string
	RoleID    string
	Namespace string
}

// CredentialCache stores kubectl ExecCredentials on disk between invocations.
//
// Expiry semantics: status.expirationTimestamp is written by the SDK with its
// early-refresh buffer already subtracted. The cache treats that value as final
// and applies no further arithmetic — the buffer is baked in once, at the point
// the raw DPA/STS/AKS expiry is known, and never re-applied here.
type CredentialCache struct {
	dir string
	now func() time.Time
}

// NewCredentialCache creates a credential cache rooted at dir.
func NewCredentialCache(dir string) *CredentialCache {
	return &CredentialCache{dir: dir, now: time.Now}
}

// pathFor returns the on-disk path for a key.
func (c *CredentialCache) pathFor(key CredentialKey) string {
	raw := strings.Join([]string{
		strings.ToUpper(key.CSP), key.FQDN, key.RoleID, key.Namespace,
	}, "\x00")
	sum := sha256.Sum256([]byte(raw))
	return filepath.Join(c.dir, "execcred_"+hex.EncodeToString(sum[:])+".json")
}

// Get returns a cached credential when one exists and is still valid.
// Any problem — missing file, unreadable JSON, loose permissions, absent or
// implausible expiry — is reported as a plain miss.
func (c *CredentialCache) Get(key CredentialKey) (*k8smodels.IdsecSCAK8sExecCredential, bool) {
	path := c.pathFor(key)

	fi, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	// A credential file readable beyond its owner cannot be trusted.
	if fi.Mode().Perm()&0o077 != 0 {
		_ = os.Remove(path)
		return nil, false
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is derived from a hashed key inside the cache dir
	if err != nil {
		return nil, false
	}

	var cred k8smodels.IdsecSCAK8sExecCredential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, false
	}

	expiry, ok := credentialExpiry(&cred)
	if !ok {
		return nil, false
	}

	now := c.now()
	if !expiry.After(now) || expiry.After(now.Add(maxCredentialLifetime)) {
		return nil, false
	}
	return &cred, true
}

// Put stores a credential. Credentials without a usable expiry are not cacheable
// and are silently dropped rather than being cached forever.
func (c *CredentialCache) Put(key CredentialKey, cred *k8smodels.IdsecSCAK8sExecCredential) error {
	if _, ok := credentialExpiry(cred); !ok {
		return nil
	}

	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return fmt.Errorf("failed to create credential cache directory: %w", err)
	}

	data, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("failed to encode credential: %w", err)
	}

	if err := os.WriteFile(c.pathFor(key), data, 0o600); err != nil {
		return fmt.Errorf("failed to write credential cache: %w", err)
	}
	return nil
}

// credentialExpiry parses status.expirationTimestamp verbatim. No buffer is
// applied: the SDK already subtracted one.
func credentialExpiry(cred *k8smodels.IdsecSCAK8sExecCredential) (time.Time, bool) {
	if cred == nil {
		return time.Time{}, false
	}
	raw := strings.TrimSpace(cred.Status.ExpirationTimestamp)
	if raw == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
