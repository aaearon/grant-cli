//go:build !(linux || darwin || dragonfly || freebsd || netbsd || openbsd || solaris)

package cmd

import (
	"errors"
	"os"
)

// errStdoutFDUnsupported reports that this platform cannot re-point the
// descriptor behind standard output at another file.
//
// Windows is the case that matters. A handle cannot be replaced in place:
// SetStdHandle only changes what GetStdHandle returns for code that asks
// afterwards, and Go built os.Stdout from the handle at process start, so an
// *os.File that captured it keeps writing to the original console or pipe.
// The stdout guard therefore falls back to its os.Stdout swap alone, which
// still contains every writer that reads os.Stdout when it runs.
var errStdoutFDUnsupported = errors.New("stdout descriptor redirection is not supported on this platform")

func reserveStdoutFD(target, sink *os.File) (*os.File, func(), error) {
	return nil, nil, errStdoutFDUnsupported
}
