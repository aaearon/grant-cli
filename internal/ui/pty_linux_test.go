package ui

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// ptySession drives a survey prompt over a real pseudo-terminal.
//
// survey refuses to render unless its input is a tty and it can put that tty into
// raw mode, so the only way to exercise the real SelectTarget/SelectGroup wiring —
// as opposed to the pure resolve* helpers — is to give it one. This uses the raw
// /dev/ptmx + TIOCSPTLCK/TIOCGPTN ioctls rather than a pty module so the repo keeps
// its zero-new-dependency goal. Linux-only by file name; the ioctl constants do not
// exist on other platforms and CI's Windows leg simply never compiles this file.
type ptySession struct {
	master *os.File
	slave  *os.File

	mu  sync.Mutex
	out bytes.Buffer
}

// newPTYSession allocates a pty, points os.Stdin and os.Stderr at the slave and
// starts draining the master. Everything is restored via t.Cleanup.
//
// Not parallel-safe: it mutates os.Stdin/os.Stderr. Callers must not call t.Parallel().
func newPTYSession(t *testing.T) *ptySession {
	t.Helper()

	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("cannot open /dev/ptmx: %v", err)
	}

	// unlockpt(3): TIOCSPTLCK with a zero value.
	var unlock int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(),
		syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		_ = master.Close()
		t.Skipf("TIOCSPTLCK failed: %v", errno)
	}

	// ptsname(3): TIOCGPTN yields the slave index.
	var ptn uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(),
		syscall.TIOCGPTN, uintptr(unsafe.Pointer(&ptn))); errno != 0 {
		_ = master.Close()
		t.Skipf("TIOCGPTN failed: %v", errno)
	}

	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", ptn), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = master.Close()
		t.Skipf("cannot open pty slave: %v", err)
	}

	p := &ptySession{master: master, slave: slave}

	origStdin, origStderr := os.Stdin, os.Stderr
	os.Stdin, os.Stderr = slave, slave

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				p.mu.Lock()
				p.out.Write(buf[:n])
				p.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() {
		os.Stdin, os.Stderr = origStdin, origStderr
		_ = slave.Close()
		_ = master.Close()
		select {
		case <-drained:
		case <-time.After(2 * time.Second):
		}
	})

	return p
}

// screen returns everything the prompt has written so far.
func (p *ptySession) screen() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}

// waitFor blocks until the prompt has rendered want. Waiting for the prompt text is
// what guarantees survey has already switched the tty into raw mode, so the keys sent
// afterwards are not mangled by the canonical line discipline.
func (p *ptySession) waitFor(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(p.screen(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q; screen so far:\n%s", want, p.screen())
}

// send writes keys in a single Write so multi-byte escape sequences cannot be split.
func (p *ptySession) send(t *testing.T, keys string) {
	t.Helper()
	if _, err := p.master.Write([]byte(keys)); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("writing %q to pty: %v", keys, err)
	}
}

const (
	keyDown  = "\x1b[B"
	keyEnter = "\r"
)

// forceInteractive makes IsInteractive() report true for the duration of the test.
//
// Not parallel: mutates the package-global ui.IsTerminalFunc.
func forceInteractive(t *testing.T) {
	t.Helper()
	orig := IsTerminalFunc
	IsTerminalFunc = func(uintptr) bool { return true }
	t.Cleanup(func() { IsTerminalFunc = orig })
}
