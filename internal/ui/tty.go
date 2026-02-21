package ui

import (
	"errors"
	"os"

	"github.com/mattn/go-isatty"
)

// IsTerminalFunc checks whether the given file descriptor is a terminal.
// It is a variable so tests can override it.
var IsTerminalFunc = func(fd uintptr) bool {
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// IsInteractive reports whether stdin is connected to a terminal.
func IsInteractive() bool {
	return IsTerminalFunc(os.Stdin.Fd())
}

// ErrNotInteractive is returned when an interactive prompt is attempted
// without a terminal attached to stdin.
var ErrNotInteractive = errors.New("interactive selection requires a terminal")
