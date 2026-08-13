//go:build windows

package k8s

import "os"

// posixPermissions is false on Windows: Go synthesizes FileMode permission bits
// from a single read-only attribute, reporting every ordinary file as 0666 and
// every directory as 0777 (os/types_windows.go). Those bits say nothing about
// who can actually read the file, and os.Chmod only toggles the read-only
// attribute — it has no ACL semantics. Applying a POSIX 0077 check here would
// reject every file unconditionally.
const posixPermissions = false

// openNoFollowFlag has no Windows equivalent; opens are unmodified.
const openNoFollowFlag = 0

// checkPrivateToCurrentUser is a no-op on Windows.
//
// Confidentiality of the credential cache relies on the ACLs Windows applies to
// the user profile directory that contains %USERPROFILE%\.grant. Enforcing it
// here would need golang.org/x/sys/windows to read the security descriptor,
// which grant does not depend on.
func checkPrivateToCurrentUser(os.FileInfo) error { return nil }
