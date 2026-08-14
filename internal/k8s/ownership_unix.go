//go:build !windows

package k8s

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// posixPermissions reports whether os.FileMode permission bits carry real
// access-control meaning on this platform.
const posixPermissions = true

// openNoFollowRead opens path for reading and refuses to traverse a final
// symlink, so the path can be inspected through the resulting descriptor
// without leaving a window for it to be swapped underneath.
func openNoFollowRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // callers pass a path they own
}

// isSymlinkOpenError reports whether an openNoFollowRead failure means the path
// was a symlink, as opposed to any other I/O failure.
//
// Linux reports ELOOP; the BSDs report EMLINK for O_NOFOLLOW specifically.
func isSymlinkOpenError(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK)
}

// checkPrivateToCurrentUser rejects a file or directory that is accessible to
// anyone but its owner, or that is owned by another user.
func checkPrivateToCurrentUser(fi os.FileInfo) error {
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("mode %o is accessible beyond its owner", perm)
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		// Unknown filesystem metadata: the permission-bit check above still applied.
		return nil
	}
	if int(stat.Uid) != os.Getuid() {
		return errors.New("owned by another user")
	}
	return nil
}
