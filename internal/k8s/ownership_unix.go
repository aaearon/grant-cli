//go:build !windows

package k8s

import (
	"errors"
	"os"
	"syscall"
)

// checkOwnedByCurrentUser rejects a path owned by another user. Root (uid 0) is
// accepted as an owner so a sudo-created cache is still usable by root itself.
func checkOwnedByCurrentUser(fi os.FileInfo) error {
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		// Unknown filesystem metadata: fall back to the permission-bit check the
		// caller already performed rather than failing closed on every platform.
		return nil
	}
	if int(stat.Uid) != os.Getuid() {
		return errors.New("path is owned by another user")
	}
	return nil
}
