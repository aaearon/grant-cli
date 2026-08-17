//go:build darwin || dragonfly || freebsd || netbsd || openbsd || solaris

package cmd

import "syscall"

// dupTo points newFD at whatever oldFD refers to.
func dupTo(oldFD, newFD int) error { return syscall.Dup2(oldFD, newFD) }
