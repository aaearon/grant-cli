package ui

import (
	"os"
	"testing"
)

// TestIsInteractive_ChecksStdinFd pins WHICH descriptor is probed, not just the
// boolean result. Every other stub in this package ignores its fd argument, so
// swapping os.Stdin.Fd() for os.Stdout.Fd() survives them all — and that swap is
// exactly what would make `grant revoke < /dev/null` in a terminal report an
// interactive session and then hang on a prompt reading closed stdin.
//
// Not parallel: mutates the package-global IsTerminalFunc.
func TestIsInteractive_ChecksStdinFd(t *testing.T) {
	original := IsTerminalFunc
	defer func() { IsTerminalFunc = original }()

	var gotFDs []uintptr
	IsTerminalFunc = func(fd uintptr) bool {
		gotFDs = append(gotFDs, fd)
		return true
	}

	IsInteractive()

	if len(gotFDs) != 1 {
		t.Fatalf("IsTerminalFunc called %d times, want exactly 1 (fds: %v)", len(gotFDs), gotFDs)
	}
	if want := os.Stdin.Fd(); gotFDs[0] != want {
		t.Errorf("IsInteractive() probed fd %d, want stdin fd %d (stdout is %d)", gotFDs[0], want, os.Stdout.Fd())
	}
}

// Not parallel: mutates the package-global IsTerminalFunc.
func TestIsInteractive_WhenTerminal(t *testing.T) {
	original := IsTerminalFunc
	defer func() { IsTerminalFunc = original }()

	IsTerminalFunc = func(fd uintptr) bool { return true }

	if !IsInteractive() {
		t.Error("IsInteractive() = false, want true when terminal")
	}
}

// Not parallel: mutates the package-global IsTerminalFunc.
func TestIsInteractive_WhenNotTerminal(t *testing.T) {
	original := IsTerminalFunc
	defer func() { IsTerminalFunc = original }()

	IsTerminalFunc = func(fd uintptr) bool { return false }

	if IsInteractive() {
		t.Error("IsInteractive() = true, want false when not terminal")
	}
}
