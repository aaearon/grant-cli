//go:build windows

package k8s

import "os"

// checkOwnedByCurrentUser is a no-op on Windows: POSIX uid semantics do not
// apply, and the ACL-based equivalent would need golang.org/x/sys/windows,
// which grant does not depend on. Windows users rely on the default per-user
// profile directory ACLs on %USERPROFILE%\.grant.
func checkOwnedByCurrentUser(os.FileInfo) error { return nil }
