//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd || solaris

package cmd

import (
	"fmt"
	"os"
	"syscall"
)

// reserveStdoutFD duplicates the descriptor behind target, re-points that
// descriptor at sink, and returns a file writing to target's original
// destination plus a restore function.
//
// Working at the descriptor level is what makes the reservation total: after
// this returns, a write to descriptor 1 lands on sink no matter which *os.File
// or which process issued it. The duplicate is marked close-on-exec so a
// subprocess cannot inherit a second route to the protocol stream.
func reserveStdoutFD(target, sink *os.File) (*os.File, func(), error) {
	targetFD := int(target.Fd())

	savedFD, err := syscall.Dup(targetFD)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to duplicate stdout: %w", err)
	}
	syscall.CloseOnExec(savedFD)

	if err := dupTo(int(sink.Fd()), targetFD); err != nil {
		_ = syscall.Close(savedFD)
		return nil, nil, fmt.Errorf("failed to redirect stdout: %w", err)
	}

	saved := os.NewFile(uintptr(savedFD), "grant-reserved-stdout")
	restore := func() {
		// Put the original destination back before dropping the duplicate,
		// otherwise the descriptor is left pointing at sink.
		_ = dupTo(savedFD, targetFD)
		_ = saved.Close()
	}
	return saved, restore, nil
}
