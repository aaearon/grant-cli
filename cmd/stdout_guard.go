package cmd

import (
	"io"
	"os"

	"github.com/spf13/cobra"
)

// stdoutGuard gives a command exclusive ownership of the process's standard
// output for the duration of its run.
//
// It exists for commands that speak a machine protocol on stdout — today only
// `grant k8s exec-credential`, whose contract with kubectl is that stdout
// contains the ExecCredential JSON and absolutely nothing else. The danger is
// not grant's own printing; it is the SDK and the libraries underneath it. The
// SDK builds loggers with log.New(os.Stdout, ...), prints its browser-redirect
// message to os.Stdout, hands os.Stdout to subprocesses, and drives Survey
// prompts (PIN entry, MFA-method selection, OOB verification, username and
// password), whose default Stdio.Out is os.Stdout. Enumerating those writers
// and silencing them one by one is how this bug got shipped twice: the list is
// not knowable from here and grows with every SDK release.
//
// So the guard takes the boundary instead of the writers. Two layers:
//
//  1. os.Stdout is pointed at os.Stderr. Every writer that reads os.Stdout when
//     it runs — the SDK logger, Survey's default Stdio, exec.Cmd.Stdout
//     assignments, the browser-redirect message — follows it to stderr without
//     knowing anything happened.
//  2. Where the platform allows it, the file descriptor behind stdout is itself
//     redirected to stderr. That also catches writers that captured os.Stdout
//     before the command started (github.com/pkg/browser holds exactly such a
//     package-level var) and subprocesses that inherit the descriptor.
//
// Data is the one writer that still reaches the real standard output: a
// descriptor duplicated before the redirect. The command writes its protocol
// payload there and nowhere else.
//
// Layer 2 is unavailable on Windows, where a descriptor cannot be re-pointed at
// another file and a captured *os.File keeps writing to the handle it was built
// from. On Windows the guarantee is therefore layer 1 only: writers that
// consult os.Stdout at call time are contained, writers that captured it at
// init time are not. Every writer named above is in the first group.
type stdoutGuard struct {
	// Data writes to the real standard output. It is only valid until Release.
	Data io.Writer

	release func()
}

// Release restores standard output. It is safe to call once, and must be
// deferred so it also runs when the command panics.
func (g *stdoutGuard) Release() {
	if g == nil || g.release == nil {
		return
	}
	g.release()
	g.release = nil
}

// stdoutOwnershipAnnotation marks a command whose stdout is a machine protocol
// rather than human output, so Execute can hand it the stdout boundary before
// Cobra runs anything at all. Driving this off an annotation rather than a
// command path keeps the decision on the command itself.
const stdoutOwnershipAnnotation = "grant.stdout"

// stdoutOwnershipProtocol is the annotation value that requests the guard.
const stdoutOwnershipProtocol = "protocol"

// installProtocolStdoutGuard reserves stdout when the command named by args
// owns it as a protocol, and returns nil otherwise. The returned guard is safe
// to Release when nil.
//
// This runs before PersistentPreRunE, which matters: the root pre-run emits the
// WSL keyring notice through the SDK logger on --verbose, and that logger is
// built on os.Stdout. A guard installed in RunE arrives after that line has
// already been written into kubectl's stdout.
//
// Find only resolves the subcommand path (it strips flags itself) and executes
// nothing, so this cannot change how any command runs. A resolution failure
// simply means no guard: the command then reserves stdout in its own RunE, as
// before.
func installProtocolStdoutGuard(root *cobra.Command, args []string) *stdoutGuard {
	target, _, err := root.Find(args)
	if err != nil || target == nil {
		return nil
	}
	if target.Annotations[stdoutOwnershipAnnotation] != stdoutOwnershipProtocol {
		return nil
	}
	return reserveStdout()
}

// activeStdoutGuard is the installed guard, if any. It exists so a command's
// RunE can ask for the reservation without caring whether Execute already made
// it — nesting yields the same Data and a no-op Release, leaving the outer
// owner responsible for restoring stdout.
var activeStdoutGuard *stdoutGuard

// reserveStdout is the seam tests replace to observe the guard.
var reserveStdout = nestingReserveStdout

func nestingReserveStdout() *stdoutGuard {
	if activeStdoutGuard != nil {
		// Nested: same writer, nil release.
		return &stdoutGuard{Data: activeStdoutGuard.Data}
	}

	g := defaultReserveStdout()
	activeStdoutGuard = g
	inner := g.release
	g.release = func() {
		activeStdoutGuard = nil
		inner()
	}
	return g
}

func defaultReserveStdout() *stdoutGuard {
	original := os.Stdout

	data := io.Writer(original)
	restoreFD := func() {}
	if saved, restore, err := reserveStdoutFD(original, os.Stderr); err == nil {
		data, restoreFD = saved, restore
	}

	os.Stdout = os.Stderr

	return &stdoutGuard{
		Data: data,
		release: func() {
			os.Stdout = original
			restoreFD()
		},
	}
}
