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

// openNoFollowFlag makes an open() refuse to traverse a final symlink, so a
// path can be opened and then inspected via its file descriptor without a
// window for the path to be swapped underneath.
const openNoFollowFlag = syscall.O_NOFOLLOW

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
