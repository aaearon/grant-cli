//go:build linux

package cmd

import "syscall"

// dupTo points newFD at whatever oldFD refers to. Linux dropped dup2 from the
// syscall table on the newer architectures (arm64 among them), so Dup3 with no
// flags is the portable spelling across every Linux target grant builds for.
func dupTo(oldFD, newFD int) error { return syscall.Dup3(oldFD, newFD, 0) }
