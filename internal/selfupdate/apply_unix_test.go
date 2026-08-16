//go:build !windows

package selfupdate

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestSyncStagedFileReportsSyncError pins that syncStagedFile propagates a
// failing f.Sync() rather than swallowing it. A silent failure would defeat the
// whole point of the fsync: minio would rename a file that may not be on disk.
//
// fsync(2) on a FIFO returns EINVAL, which is the only portable-ish way to make
// Sync fail on a file that opens cleanly. Unix only - Windows has no mkfifo.
func TestSyncStagedFileReportsSyncError(t *testing.T) {
	target := filepath.Join(t.TempDir(), "grant")
	staged := stagedPath(target)

	if err := syscall.Mkfifo(staged, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(staged) })

	// Assert the error is the fsync failure, not an open failure. Without this
	// the test degrades silently: on a Unix where os.OpenFile(fifo, O_RDWR)
	// fails, syncStagedFile returns the OPEN error, `err != nil` still holds,
	// and the test would pass with the mutation applied.
	err := syncStagedFile(target)
	if err == nil {
		t.Fatal("expected the failing fsync to be reported, got nil")
	}
	if !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		t.Fatalf("expected the fsync error (EINVAL/ENOTSUP), got %v - the FIFO probably failed to open, which makes this test inert", err)
	}
}
