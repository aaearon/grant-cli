package k8s

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
//
// OrganizationID is part of the key: the same cluster FQDN and role ID can be
// reached through different Entra tenants / AWS organizations, and a credential
// minted for one must never be replayed for another.
type CredentialKey struct {
	CSP            string
	FQDN           string
	RoleID         string
	Namespace      string
	OrganizationID string
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

	// Warn, when set, receives a message whenever an entry is rejected for a
	// security reason. A rejection silently degrades into a fresh login, so the
	// user deserves to know why. Ordinary misses and expiries are not reported.
	Warn func(msg string)
}

// NewCredentialCache creates a credential cache rooted at dir.
func NewCredentialCache(dir string) *CredentialCache {
	return &CredentialCache{dir: dir, now: time.Now}
}

func (c *CredentialCache) warn(format string, args ...any) {
	if c.Warn == nil {
		return
	}
	c.Warn(fmt.Sprintf(format, args...))
}

// pathFor returns the on-disk path for a key.
func (c *CredentialCache) pathFor(key CredentialKey) string {
	raw := strings.Join([]string{
		strings.ToUpper(key.CSP), key.FQDN, key.RoleID, key.Namespace, key.OrganizationID,
	}, "\x00")
	sum := sha256.Sum256([]byte(raw))
	return filepath.Join(c.dir, "execcred_"+hex.EncodeToString(sum[:])+".json")
}

// Get returns a cached credential when one exists and is trustworthy.
//
// Any doubt is reported as a plain miss: a missing file, a symlink or anything
// that is not a regular file, a file or directory readable beyond the owner, a
// file owned by another user, unreadable JSON, or an absent/implausible expiry.
// Untrustworthy files are removed so the next run re-mints the credential.
func (c *CredentialCache) Get(key CredentialKey) (*k8smodels.IdsecSCAK8sExecCredential, bool) {
	path := c.pathFor(key)

	if err := c.checkDirSecure(); err != nil {
		// A cache directory that does not exist yet is the first run, not a
		// security event. Warning about it would greet every new install with a
		// scary message on the very first kubectl call.
		if !os.IsNotExist(err) {
			c.warn("ignoring the credential cache: %s is not usable (%v); re-authenticating instead", c.dir, err)
		}
		return nil, false
	}

	data, err := c.readEntry(path)
	if err != nil {
		if !os.IsNotExist(err) {
			c.warn("ignoring cached credential %s (%v); re-authenticating instead", path, err)
		}
		return nil, false
	}

	var cred k8smodels.IdsecSCAK8sExecCredential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, false
	}
	if !isUsableCredential(&cred) {
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
//
// The file is created fresh in the cache directory with O_EXCL at mode 0600 and
// renamed over any previous entry, so a pre-existing file with loose permissions
// is replaced rather than written into.
func (c *CredentialCache) Put(key CredentialKey, cred *k8smodels.IdsecSCAK8sExecCredential) error {
	if _, ok := credentialExpiry(cred); !ok {
		return nil
	}
	if !isUsableCredential(cred) {
		return nil
	}

	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return fmt.Errorf("failed to create credential cache directory: %w", err)
	}
	// Tighten a pre-existing cache directory rather than writing secrets into a
	// world-readable one. Skipped on Windows, where Chmod only toggles the
	// read-only attribute and would make the directory unwritable.
	if posixPermissions {
		if err := os.Chmod(c.dir, 0o700); err != nil {
			return fmt.Errorf("failed to secure credential cache directory: %w", err)
		}
	}

	data, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("failed to encode credential: %w", err)
	}

	return writeSecretFileAtomic(c.pathFor(key), data)
}

// writeSecretFileAtomic creates a new 0600 file in the target's directory with
// O_EXCL and renames it over the target. It never writes into a file it did not
// create, so an attacker-planted file or symlink cannot receive the secret.
func writeSecretFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".grant-cred-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create credential cache file: %w", err)
	}
	tmpName := tmp.Name()

	if err := writeAndSecure(tmp, data); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to store credential: %w", err)
	}
	return nil
}

func writeAndSecure(f *os.File, data []byte) error {
	defer func() { _ = f.Close() }()

	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("failed to secure credential cache file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("failed to write credential: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to flush credential: %w", err)
	}
	return nil
}

// readEntry opens the entry and validates it through the resulting file
// descriptor, so the file that is checked is exactly the file that is read.
// A path-based Lstat followed by a read would leave a window for the entry to
// be swapped for a symlink in between.
//
// Entries that fail validation are removed. os.Remove on a symlink removes the
// link, never its target.
//
// Only a symlink earns removal. An earlier version treated *every* non-ENOENT
// open failure as "symlink, or not a regular file" and deleted the entry, so
// descriptor exhaustion or a transient I/O error would destroy a perfectly good
// credential and discard the real cause with it. Those errors now propagate
// untouched; the caller reports them and re-authenticates for this one run.
func (c *CredentialCache) readEntry(path string) ([]byte, error) {
	f, err := openNoFollowRead(path)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return nil, err
		case isSymlinkOpenError(err):
			_ = os.Remove(path)
			return nil, errors.New("it is a symlink")
		default:
			return nil, err
		}
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		_ = os.Remove(path)
		return nil, errors.New("it is not a regular file")
	}
	if posixPermissions {
		if err := checkPrivateToCurrentUser(fi); err != nil {
			_ = os.Remove(path)
			return nil, err
		}
	}

	return io.ReadAll(f)
}

// checkDirSecure rejects a cache directory that is a symlink, is not a
// directory, or is accessible beyond the owner.
func (c *CredentialCache) checkDirSecure() error {
	fi, err := os.Lstat(c.dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("it is a symlink")
	}
	if !fi.IsDir() {
		return errors.New("it is not a directory")
	}
	if !posixPermissions {
		return nil
	}
	return checkPrivateToCurrentUser(fi)
}

// isUsableCredential rejects a decoded credential that carries no actual
// credential material, so a truncated or hand-crafted file is not replayed.
func isUsableCredential(cred *k8smodels.IdsecSCAK8sExecCredential) bool {
	if cred == nil {
		return false
	}
	if strings.TrimSpace(cred.Status.Token) != "" {
		return true
	}
	return strings.TrimSpace(cred.Status.ClientCertificateData) != "" &&
		strings.TrimSpace(cred.Status.ClientKeyData) != ""
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
