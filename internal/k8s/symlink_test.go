package k8s

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// mustSymlink creates a symlink, or skips the test when the platform will not
// let an unprivileged process create one.
//
// Windows requires either administrator rights or Developer Mode for
// os.Symlink. Skipping on *that* is honest — the machine cannot stage the
// attack — and is a different thing from skipping the whole test on Windows
// because symlink handling there was never implemented, which is what used to
// happen and is what let the no-follow regression through.
func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("this machine will not create symlinks (needs Developer Mode or admin): %v", err)
		}
		t.Fatal(err)
	}
}

// TestOpenNoFollowReadRefusesSymlink pins the platform primitive itself, one
// level below the cache and the backup that depend on it. A future port that
// defines the no-follow behavior as "do nothing" — as the Windows file once
// did with openNoFollowFlag = 0 — fails here first.
func TestOpenNoFollowReadRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, target, link)

	f, err := openNoFollowRead(link)
	if err == nil {
		_ = f.Close()
		t.Fatal("openNoFollowRead followed a symlink; every caller's symlink guarantee rests on it not doing that")
	}
	if !isSymlinkOpenError(err) {
		t.Errorf("error %v is not classified as a symlink refusal, so callers will treat it as an I/O fault", err)
	}
	if os.IsNotExist(err) {
		t.Error("a symlink refusal must not look like a missing file")
	}
}

// TestOpenNoFollowReadOpensRegularFile keeps the refusal from degenerating into
// "refuse everything".
func TestOpenNoFollowReadOpensRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := openNoFollowRead(path)
	if err != nil {
		t.Fatalf("openNoFollowRead: %v", err)
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Errorf("mode = %v, want a regular file", fi.Mode())
	}
}

// TestOpenNoFollowReadReportsMissingFile keeps ENOENT distinguishable, which is
// what lets the cache treat an absent entry as an ordinary miss.
func TestOpenNoFollowReadReportsMissingFile(t *testing.T) {
	_, err := openNoFollowRead(filepath.Join(t.TempDir(), "absent"))
	if !os.IsNotExist(err) {
		t.Fatalf("err = %v, want a not-exist error", err)
	}
	if isSymlinkOpenError(err) {
		t.Error("a missing file must not be classified as a symlink")
	}
}
