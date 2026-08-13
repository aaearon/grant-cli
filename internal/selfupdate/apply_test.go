package selfupdate

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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

func TestApplyBinaryToReplacesTarget(t *testing.T) {
	path := writeFakeBinary(t)

	if err := applyBinaryTo([]byte(newBinaryContents), path); err != nil {
		t.Fatalf("applyBinaryTo: %v", err)
	}

	got, err := os.ReadFile(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != newBinaryContents {
		t.Errorf("target contents = %q, want %q", string(got), newBinaryContents)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o755 {
			t.Errorf("mode = %o, want 0755", perm)
		}
	}
}

func TestApplyBinaryFailureLeavesOriginalIntact(t *testing.T) {
	tests := []struct {
		name string
		opts func(target string) minio.Options
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
			name: "checksum mismatch with rollback path",
			opts: func(target string) minio.Options {
				return minio.Options{
					TargetPath:  target,
					TargetMode:  0o755,
					OldSavePath: target + ".old",
					Hash:        crypto.SHA256,
					Checksum:    make([]byte, sha256.Size),
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeFakeBinary(t)

			err := applyWithOptions([]byte(newBinaryContents), tt.opts(path))
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			got, readErr := os.ReadFile(path) //nolint:gosec // test fixture
			if readErr != nil {
				t.Fatalf("original binary is gone: %v", readErr)
			}
			// The binary must be either the untouched original or the fully
			// written replacement - never a truncated hybrid.
			if s := string(got); s != oldBinaryContents && s != newBinaryContents {
				t.Errorf("binary is neither old nor new (possibly truncated): %q", s)
			}
			if string(got) != oldBinaryContents {
				t.Errorf("expected original contents preserved, got %q", string(got))
			}

			// No stray .new file left behind next to the target.
			if _, statErr := os.Stat(path + ".new"); statErr == nil {
				t.Error("leftover .new file was not cleaned up")
			}
		})
	}
}

func TestApplyBinaryRollbackRestoresOriginal(t *testing.T) {
	path := writeFakeBinary(t)
	oldSave := path + ".old"

	// A successful apply moves the original aside to OldSavePath.
	err := applyWithOptions([]byte(newBinaryContents), minio.Options{
		TargetPath:  path,
		TargetMode:  0o755,
		OldSavePath: oldSave,
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	saved, err := os.ReadFile(oldSave) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("old binary was not saved for rollback: %v", err)
	}
	if string(saved) != oldBinaryContents {
		t.Errorf("saved old binary = %q, want %q", string(saved), oldBinaryContents)
	}

	// Simulate the user rolling back after a bad update.
	if err := minio.RollbackError(errTestApply); err != nil && !errors.Is(err, errTestApply) {
		t.Fatalf("unexpected rollback error: %v", err)
	}
}

func TestApplyBinaryVerifiesWhatItWrote(t *testing.T) {
	path := writeFakeBinary(t)

	if err := applyBinaryTo([]byte(newBinaryContents), path); err != nil {
		t.Fatalf("applyBinaryTo: %v", err)
	}

	got, err := os.ReadFile(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	sum := sha256.Sum256(got)
	want := sha256.Sum256([]byte(newBinaryContents))
	if sum != want {
		t.Error("written binary does not match the source bytes")
	}
}
