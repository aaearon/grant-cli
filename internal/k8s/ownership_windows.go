//go:build windows

package k8s

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// posixPermissions is false on Windows: Go synthesizes FileMode permission bits
// from a single read-only attribute, reporting every ordinary file as 0666 and
// every directory as 0777 (os/types_windows.go). Those bits say nothing about
// who can actually read the file, and os.Chmod only toggles the read-only
// attribute — it has no ACL semantics. Applying a POSIX 0077 check here would
// reject every file unconditionally.
const posixPermissions = false

// errSymlinkRefused reports that a path was a reparse point (a symlink, a
// junction or a mount point) and was refused rather than followed.
var errSymlinkRefused = errors.New("it is a symlink or other reparse point")

// openNoFollowRead is the Windows counterpart of O_NOFOLLOW.
//
// An earlier version of this file defined the no-follow open flag as 0, which
// silently turned every symlink check on Windows into a no-op: the cache opened
// symlinks normally, f.Stat() then described the *target*, and BackupOnce
// dereferenced a symlinked kubeconfig despite documenting that it refuses one.
// Mapping a security primitive to zero on a platform that lacks it is not a
// port, it is a hole.
//
// Windows has the primitive, it is just spelled differently.
// FILE_FLAG_OPEN_REPARSE_POINT makes CreateFile open the reparse point itself
// instead of its target, so the handle refers to the link, never to what it
// points at. Asking that handle for its attributes then tells us whether we
// were handed a link, with no window in between for the path to be swapped —
// the same descriptor-based discipline the POSIX path relies on.
// FILE_FLAG_BACKUP_SEMANTICS is required for the call to accept directories.
func openNoFollowRead(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	h, err := windows.CreateFile(
		p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(h), path)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(h), &info); err != nil {
		_ = f.Close()
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = f.Close()
		return nil, &os.PathError{Op: "open", Path: path, Err: errSymlinkRefused}
	}
	return f, nil
}

// isSymlinkOpenError reports whether an openNoFollowRead failure means the path
// was a symlink, as opposed to any other I/O failure.
func isSymlinkOpenError(err error) bool { return errors.Is(err, errSymlinkRefused) }

// checkPrivateToCurrentUser is a no-op on Windows, and this is a real gap, not
// a platform equivalence.
//
// On POSIX the credential cache verifies that each file is owned by the calling
// user and is unreadable by anyone else. Neither check is performed here.
// Confidentiality of %USERPROFILE%\.grant rests entirely on the ACLs Windows
// applies to the user profile directory by default. If a machine's profile ACLs
// have been loosened, or the cache directory was created by another account,
// grant will not notice. Closing it needs the file's security descriptor
// (GetSecurityInfo) compared against the process token's user SID, plus a DACL
// walk for the "no one else may read" half; that is not implemented.
func checkPrivateToCurrentUser(os.FileInfo) error { return nil }
