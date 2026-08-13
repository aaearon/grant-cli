package ui

import "testing"

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
