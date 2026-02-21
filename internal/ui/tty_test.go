package ui

import "testing"

func TestIsInteractive_WhenTerminal(t *testing.T) {
	t.Parallel()
	original := IsTerminalFunc
	defer func() { IsTerminalFunc = original }()

	IsTerminalFunc = func(fd uintptr) bool { return true }

	if !IsInteractive() {
		t.Error("IsInteractive() = false, want true when terminal")
	}
}

func TestIsInteractive_WhenNotTerminal(t *testing.T) {
	t.Parallel()
	original := IsTerminalFunc
	defer func() { IsTerminalFunc = original }()

	IsTerminalFunc = func(fd uintptr) bool { return false }

	if IsInteractive() {
		t.Error("IsInteractive() = true, want false when not terminal")
	}
}
