package selfupdate

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	minio "github.com/minio/selfupdate"
)

// Durability and atomicity, precisely:
//
// The replacement is staged as a sibling file, fsync'ed, and then swapped in
// by github.com/minio/selfupdate with two renames:
//
//	1. rename(target, .target.old)
//	2. rename(.target.new, target)
//
// Each rename is individually atomic, so the target is never a partially
// written file. The *pair* is not atomic: if the process is killed between
// step 1 and step 2, or if step 2 and the rollback rename both fail, the
// target path is left ABSENT with .target.old and .target.new beside it. That
// window is small but real, and it cannot be closed without a different
// replacement strategy. When grant detects it, it prints the exact command to
// restore the old binary; see recoveryHint.
//
// The fsync in syncStagedFile is grant's, not minio's: minio writes and closes
// the staged file without syncing it, so a crash or power loss between the
// write and the rename could otherwise leave a zero-length or partially
// materialized .target.new to be renamed into place.

// applyFns are indirections so tests can drive the failure paths.
var (
	prepareFn = minio.PrepareAndCheckBinary
	commitFn  = minio.CommitBinary
)

// applyBinary replaces the currently running executable with newBinary.
func applyBinary(newBinary []byte) error {
	return applyBinaryTo(newBinary, "")
}

// applyBinaryTo replaces the binary at targetPath. An empty targetPath means
// the running executable.
func applyBinaryTo(newBinary []byte, targetPath string) error {
	sum := sha256.Sum256(newBinary)
	return applyWithOptions(bytes.NewReader(newBinary), minio.Options{
		TargetPath: targetPath,
		TargetMode: 0o755, // release binaries are always installed executable
		Hash:       crypto.SHA256,
		Checksum:   sum[:],
	})
}

// applyWithOptions stages, syncs and commits the replacement. It is the single
// seam onto minio/selfupdate.
func applyWithOptions(update io.Reader, opts minio.Options) error {
	target, err := resolveTargetPath(opts.TargetPath)
	if err != nil {
		return fmt.Errorf("failed to locate the binary to replace: %w", err)
	}

	if err := prepareFn(update, opts); err != nil {
		return err
	}

	// minio closes the staged file but never syncs it; do that before any
	// rename so a crash cannot promote a partially materialized file.
	if err := syncStagedFile(target); err != nil {
		_ = os.Remove(stagedPath(target))
		return fmt.Errorf("failed to flush the staged binary to disk: %w", err)
	}

	if err := commitFn(opts); err != nil {
		return wrapApplyError(err, minio.RollbackError(err), target)
	}

	// Best effort: make the rename itself durable. Not supported on every
	// platform or filesystem, so failures here are not fatal - the swap has
	// already happened.
	syncDir(filepath.Dir(target))
	return nil
}

// resolveTargetPath mirrors minio's Options.getPath.
func resolveTargetPath(targetPath string) (string, error) {
	if targetPath != "" {
		return targetPath, nil
	}
	return os.Executable()
}

// stagedPath mirrors the staged filename minio writes.
func stagedPath(targetPath string) string {
	return filepath.Join(filepath.Dir(targetPath), "."+filepath.Base(targetPath)+".new")
}

// oldPathFor mirrors the backup filename minio renames the current binary to
// when OldSavePath is not set.
func oldPathFor(targetPath string) string {
	return filepath.Join(filepath.Dir(targetPath), "."+filepath.Base(targetPath)+".old")
}

// syncStagedFile fsyncs the staged replacement binary.
func syncStagedFile(targetPath string) error {
	f, err := os.OpenFile(stagedPath(targetPath), os.O_RDWR, 0o600) //nolint:gosec // path derived from the target binary
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// syncDir fsyncs a directory so a completed rename survives a crash. Best
// effort: several platforms and filesystems refuse this.
func syncDir(dir string) {
	d, err := os.Open(dir) //nolint:gosec // directory of the target binary
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// wrapApplyError turns a commit failure into an actionable error. rollbackErr
// is the result of minio.RollbackError(err): non-nil means the original binary
// could not be put back and the user must intervene.
func wrapApplyError(err, rollbackErr error, targetPath string) error {
	if rollbackErr == nil {
		return err
	}
	return fmt.Errorf("update failed and the rollback also failed, so %s no longer exists; %s: %w",
		targetPath, recoveryHint(targetPath), errors.Join(err, rollbackErr))
}

// recoveryHint spells out how to restore the previous binary by hand after an
// interrupted or half-failed update.
func recoveryHint(targetPath string) string {
	return fmt.Sprintf("restore it with: mv %q %q", oldPathFor(targetPath), targetPath)
}

// InterruptedUpdate reports whether targetPath looks like a previous update
// that was interrupted between the two renames - the binary is missing but its
// backup is still there - and returns the command that repairs it.
func InterruptedUpdate(targetPath string) (hint string, interrupted bool) {
	if _, err := os.Stat(targetPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return "", false
	}
	if _, err := os.Stat(oldPathFor(targetPath)); err != nil {
		return "", false
	}
	return recoveryHint(targetPath), true
}
