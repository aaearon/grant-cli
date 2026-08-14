package selfupdate

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	minio "github.com/minio/selfupdate"
)

var errTestApply = errors.New("apply failed")

const (
	oldBinaryContents = "OLD BINARY CONTENTS"
	newBinaryContents = "NEW BINARY CONTENTS - LONGER THAN THE OLD ONE"
)

// writeFakeBinary creates a stand-in for the running executable.
func writeFakeBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grant")
	if err := os.WriteFile(path, []byte(oldBinaryContents), 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatalf("write fake binary: %v", err)
	}
	return path
}

// readFile is a fatal-on-error helper.
func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// assertNotTruncated pins the core safety property: whatever happens, the
// binary on disk is either the complete old one or the complete new one.
func assertNotTruncated(t *testing.T, path string) {
	t.Helper()
	got := readFile(t, path)
	if got != oldBinaryContents && got != newBinaryContents {
		t.Fatalf("binary is neither the old nor the new one (truncated?): %q", got)
	}
}

func TestApplyBinaryToReplacesTarget(t *testing.T) {
	path := writeFakeBinary(t)

	if err := applyBinaryTo([]byte(newBinaryContents), path); err != nil {
		t.Fatalf("applyBinaryTo: %v", err)
	}

	if got := readFile(t, path); got != newBinaryContents {
		t.Errorf("target contents = %q, want %q", got, newBinaryContents)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		// The installed mode is always 0755: release archives carry the
		// binary and grant deliberately ignores archive modes.
		if perm := info.Mode().Perm(); perm != 0o755 {
			t.Errorf("mode = %o, want 0755", perm)
		}
	}

	if _, err := os.Stat(stagedPath(path)); err == nil {
		t.Error("staged .new file was left behind after a successful apply")
	}
	if _, err := os.Stat(oldPathFor(path)); err == nil {
		t.Error("backup .old file was left behind after a successful apply")
	}
}

// TestApplyBinaryFailsBeforeTouchingTarget covers the failures that happen
// while staging, i.e. before the original binary is renamed at all.
func TestApplyBinaryFailsBeforeTouchingTarget(t *testing.T) {
	tests := []struct {
		name   string
		update func() io.Reader
		opts   func(target string) minio.Options
		setup  func(t *testing.T, target string)
	}{
		{
			name: "checksum mismatch",
			opts: func(target string) minio.Options {
				return minio.Options{
					TargetPath: target,
					TargetMode: 0o755,
					Hash:       crypto.SHA256,
					Checksum:   make([]byte, sha256.Size), // all zeroes: cannot match
				}
			},
		},
		{
			name: "target directory does not exist",
			opts: func(target string) minio.Options {
				return minio.Options{
					TargetPath: filepath.Join(target, "no", "such", "dir", "grant"),
					TargetMode: 0o755,
				}
			},
		},
		{
			name: "partial staged write: source reader fails mid-stream",
			update: func() io.Reader {
				return io.MultiReader(
					strings.NewReader(newBinaryContents[:10]),
					&failingReader{err: errTestApply},
				)
			},
			opts: func(target string) minio.Options {
				return minio.Options{TargetPath: target, TargetMode: 0o755}
			},
		},
		{
			name: "unwritable target directory",
			setup: func(t *testing.T, target string) {
				if runtime.GOOS == "windows" {
					t.Skip("chmod 0500 does not deny directory writes on Windows")
				}
				if os.Geteuid() == 0 {
					t.Skip("running as root: directory permissions are not enforced")
				}
				if err := os.Chmod(filepath.Dir(target), 0o500); err != nil {
					t.Fatalf("chmod: %v", err)
				}
				t.Cleanup(func() { _ = os.Chmod(filepath.Dir(target), 0o700) })
			},
			opts: func(target string) minio.Options {
				return minio.Options{TargetPath: target, TargetMode: 0o755}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeFakeBinary(t)
			if tt.setup != nil {
				tt.setup(t, path)
			}

			var update io.Reader = bytes.NewReader([]byte(newBinaryContents))
			if tt.update != nil {
				update = tt.update()
			}

			if err := applyWithOptions(update, tt.opts(path)); err == nil {
				t.Fatal("expected error, got nil")
			}

			assertNotTruncated(t, path)
			if got := readFile(t, path); got != oldBinaryContents {
				t.Errorf("expected original contents preserved, got %q", got)
			}
			if _, err := os.Stat(stagedPath(path)); err == nil {
				t.Error("leftover .new file was not cleaned up")
			}
		})
	}
}

// TestApplyBinaryRollsBackWhenSecondRenameFails drives the real rollback path:
// the current binary has already been renamed away when the second rename
// fails, and minio must put it back.
func TestApplyBinaryRollsBackWhenSecondRenameFails(t *testing.T) {
	path := writeFakeBinary(t)

	// Stage normally, then delete the staged file so that minio's second
	// rename (.grant.new -> grant) fails after the first has succeeded.
	origCommit := commitFn
	defer func() { commitFn = origCommit }()
	commitFn = func(opts minio.Options) error {
		if err := os.Remove(stagedPath(path)); err != nil {
			t.Fatalf("remove staged file: %v", err)
		}
		return origCommit(opts)
	}

	err := applyWithOptions(bytes.NewReader([]byte(newBinaryContents)), minio.Options{
		TargetPath: path,
		TargetMode: 0o755,
	})
	if err == nil {
		t.Fatal("expected the commit to fail, got nil")
	}

	// Rollback succeeded, so the error must NOT claim otherwise.
	if minio.RollbackError(err) != nil {
		t.Errorf("rollback unexpectedly failed: %v", minio.RollbackError(err))
	}
	if strings.Contains(err.Error(), "no longer exists") {
		t.Errorf("error wrongly reports an unrecoverable state: %v", err)
	}

	assertNotTruncated(t, path)
	if got := readFile(t, path); got != oldBinaryContents {
		t.Errorf("rollback did not restore the original: got %q", got)
	}
	if _, err := os.Stat(oldPathFor(path)); err == nil {
		t.Error(".old backup should have been renamed back, not left in place")
	}
}

// TestApplyBinaryRollbackFailureIsReported covers the unrecoverable case: the
// commit failed AND the rollback failed, so the target no longer exists.
func TestApplyBinaryRollbackFailureIsReported(t *testing.T) {
	path := writeFakeBinary(t)

	origCommit := commitFn
	defer func() { commitFn = origCommit }()
	commitFn = func(opts minio.Options) error {
		// Reproduce the exact end state minio leaves behind: the binary has
		// been renamed to its backup and neither the new file nor the
		// rollback could take its place.
		if err := os.Rename(path, oldPathFor(path)); err != nil {
			t.Fatalf("simulate first rename: %v", err)
		}
		if err := os.Remove(stagedPath(path)); err != nil {
			t.Fatalf("remove staged file: %v", err)
		}
		return errTestApply
	}

	err := applyWithOptions(bytes.NewReader([]byte(newBinaryContents)), minio.Options{
		TargetPath: path,
		TargetMode: 0o755,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// The target is genuinely gone; the user must be told exactly how to fix it.
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected the target to be absent, stat gave: %v", statErr)
	}
	hint, interrupted := InterruptedUpdate(path)
	if !interrupted {
		t.Fatal("InterruptedUpdate did not detect the interrupted state")
	}
	// recoveryHint renders the paths with %q, so compare against the quoted
	// form - on Windows the raw path contains backslashes that %q escapes.
	if !strings.Contains(hint, strconv.Quote(oldPathFor(path))) || !strings.Contains(hint, strconv.Quote(path)) {
		t.Errorf("recovery hint does not name both paths: %q", hint)
	}

	// And the documented recovery actually works.
	if err := os.Rename(oldPathFor(path), path); err != nil {
		t.Fatalf("documented recovery failed: %v", err)
	}
	if got := readFile(t, path); got != oldBinaryContents {
		t.Errorf("recovered binary = %q, want the original", got)
	}
}

// TestWrapApplyError pins the message contract, including the rollback-failed
// wording that cannot be provoked deterministically through minio itself.
func TestWrapApplyError(t *testing.T) {
	rollbackFailed := errors.New("rename back failed")

	t.Run("rollback succeeded returns the original error", func(t *testing.T) {
		got := wrapApplyError(errTestApply, nil, "/usr/local/bin/grant")
		if !errors.Is(got, errTestApply) {
			t.Errorf("error does not wrap the original: %v", got)
		}
		if strings.Contains(got.Error(), "no longer exists") {
			t.Errorf("unexpected unrecoverable wording: %v", got)
		}
	})

	t.Run("rollback failed reports recovery", func(t *testing.T) {
		got := wrapApplyError(errTestApply, rollbackFailed, "/usr/local/bin/grant")
		if !errors.Is(got, errTestApply) || !errors.Is(got, rollbackFailed) {
			t.Errorf("error must wrap both causes: %v", got)
		}
		for _, want := range []string{"/usr/local/bin/grant", ".grant.old", "mv"} {
			if !strings.Contains(got.Error(), want) {
				t.Errorf("message missing %q: %v", want, got)
			}
		}
	})
}

// TestInterruptedUpdate covers detection of a process killed between the two
// renames, and the cases that must NOT be reported as interrupted.
func TestInterruptedUpdate(t *testing.T) {
	t.Run("target missing with backup present", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "grant")
		if err := os.WriteFile(oldPathFor(path), []byte(oldBinaryContents), 0o755); err != nil { //nolint:gosec // test fixture
			t.Fatalf("write backup: %v", err)
		}
		if _, ok := InterruptedUpdate(path); !ok {
			t.Error("expected the interrupted state to be detected")
		}
	})

	t.Run("healthy install", func(t *testing.T) {
		path := writeFakeBinary(t)
		if hint, ok := InterruptedUpdate(path); ok {
			t.Errorf("healthy install reported as interrupted: %q", hint)
		}
	})

	t.Run("target missing without backup", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "grant")
		if _, ok := InterruptedUpdate(path); ok {
			t.Error("missing binary without a backup must not be reported as interrupted")
		}
	})
}

// TestApplyBinaryStagedFileIsSynced pins that grant syncs the staged file
// before any rename - minio does not.
func TestApplyBinaryStagedFileIsSynced(t *testing.T) {
	path := writeFakeBinary(t)

	synced := false
	origCommit := commitFn
	defer func() { commitFn = origCommit }()
	commitFn = func(opts minio.Options) error {
		// By commit time the staged file must exist and hold the full
		// replacement; syncStagedFile ran just before this.
		staged, err := os.ReadFile(stagedPath(path)) //nolint:gosec // test fixture
		if err != nil {
			t.Fatalf("staged file missing at commit time: %v", err)
		}
		if string(staged) != newBinaryContents {
			t.Errorf("staged file = %q, want the full replacement", string(staged))
		}
		synced = true
		return origCommit(opts)
	}

	if err := applyBinaryTo([]byte(newBinaryContents), path); err != nil {
		t.Fatalf("applyBinaryTo: %v", err)
	}
	if !synced {
		t.Error("commit step never ran")
	}
}

// TestApplyBinaryToSymlink documents what happens when the install path is a
// symlink: the link itself is replaced by a regular file and the link target
// is left untouched. On Linux and macOS os.Executable resolves symlinks, so
// the real run replaces the resolved binary, not the link.
func TestApplyBinaryToSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows and are untested here")
	}

	dir := t.TempDir()
	targetFile := filepath.Join(dir, "grant-real")
	link := filepath.Join(dir, "grant")
	if err := os.WriteFile(targetFile, []byte(oldBinaryContents), 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatalf("write real binary: %v", err)
	}
	if err := os.Symlink(targetFile, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := applyBinaryTo([]byte(newBinaryContents), link); err != nil {
		t.Fatalf("applyBinaryTo: %v", err)
	}

	if got := readFile(t, link); got != newBinaryContents {
		t.Errorf("link path contents = %q, want the replacement", got)
	}
	if got := readFile(t, targetFile); got != oldBinaryContents {
		t.Errorf("symlink target was modified: %q", got)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Error("expected the symlink to have been replaced by a regular file")
	}
}

// failingReader returns an error after being read from.
type failingReader struct{ err error }

func (f *failingReader) Read([]byte) (int, error) { return 0, f.err }
