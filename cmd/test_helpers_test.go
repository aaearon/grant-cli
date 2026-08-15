// NOTE: Do not use t.Parallel() in cmd/ tests due to package-level state
// (verbose, passedArgValidation) that is mutated during test execution.
package cmd

import (
	"bytes"
	"os"
	"testing"

	"github.com/aaearon/grant-cli/internal/ui"
	"github.com/spf13/cobra"
)

// withInteractiveTTY forces ui.IsInteractive() to the given answer for the
// duration of the test, restoring the package global via t.Cleanup.
//
// Use it in every test whose behavior depends on interactivity: `go test`
// happens to run with a non-TTY stdin, but that is an accident of the harness,
// not an assertion, and it silently reverses under a PTY.
func withInteractiveTTY(t *testing.T, interactive bool) {
	t.Helper()
	orig := ui.IsTerminalFunc
	t.Cleanup(func() { ui.IsTerminalFunc = orig })
	ui.IsTerminalFunc = func(_ uintptr) bool { return interactive }
}

// withDiscardedStdout points os.Stdout at a throwaway file for the duration of
// the test, restoring it via t.Cleanup.
//
// survey writes its prompts straight to os.Stdout rather than to the cobra
// output buffer, so any test that reaches a prompt sprays terminal control
// sequences over the developer's console. One of them, ESC[6n (Device Status
// Report), makes the terminal write its reply back on stdin, which corrupts the
// shell prompt after `go test`. Redirecting os.Stdout keeps that off the real
// terminal without adding a production seam to the prompting code.
func withDiscardedStdout(t *testing.T) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout-")
	if err != nil {
		t.Fatalf("creating stdout sink: %v", err)
	}
	orig := os.Stdout
	t.Cleanup(func() {
		os.Stdout = orig
		_ = f.Close()
	})
	os.Stdout = f
}

// newTestRootCommand creates a root command for testing (no elevation RunE)
func newTestRootCommand() *cobra.Command {
	return newRootCommand(nil)
}

// newNoOpCommand creates a minimal command for testing PersistentPreRunE
func newNoOpCommand() *cobra.Command {
	return &cobra.Command{
		Use:  "noop",
		RunE: func(cmd *cobra.Command, args []string) error { return nil },
	}
}

// executeCommand executes a command and returns its output.
// When SilenceErrors is true, error text is appended to the output buffer
// to match production behavior (where Execute() prints the error).
func executeCommand(cmd *cobra.Command, args ...string) (string, error) {
	defer restoreCommandGlobals(outputFormat, verbose)

	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)

	err := cmd.Execute()
	if err != nil {
		buf.WriteString(err.Error() + "\n")
	}
	return buf.String(), err
}

// restoreCommandGlobals puts back the two package-globals that newRootCommand
// binds to persistent flags: outputFormat (--output, StringVarP) and verbose
// (--verbose, BoolVarP). Executing any command carrying those flags leaves both
// globals set for every later test, and a command built without the root flag
// set (NewEnvCommandWithDeps, for instance) then inherits the previous test's
// values — an order dependence that only shows up under `go test -shuffle=on`.
//
// outputFormat is the load-bearing half: making this a no-op fails on 5 of 8
// fixed shuffle seeds. verbose is latent today, because pflag rewrites it to
// the registered default whenever newRootCommand runs, but it is the same leak
// through the same mechanism and is restored for the same reason.
func restoreCommandGlobals(savedOutput string, savedVerbose bool) {
	outputFormat = savedOutput
	verbose = savedVerbose
}

// executeCommandStreams executes a command keeping stdout and stderr apart and
// writing no error text into either. Use it when a test needs to assert on the
// exact stdout payload (e.g. valid JSON) *and* on a returned error, which
// executeCommand cannot express because it merges the streams and appends the
// error text.
func executeCommandStreams(cmd *cobra.Command, args ...string) (stdout, stderr string, err error) {
	defer restoreCommandGlobals(outputFormat, verbose)

	var outBuf, errBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)

	err = cmd.Execute()
	return outBuf.String(), errBuf.String(), err
}

// executeWithHint simulates Execute() logic without os.Exit, returning the error output.
// Used for testing the verbose hint behavior.
func executeWithHint(cmd *cobra.Command, args []string) string {
	defer restoreCommandGlobals(outputFormat, verbose)

	passedArgValidation = false
	cmd.SetArgs(args)
	err := cmd.Execute()
	if err == nil {
		return ""
	}
	out := err.Error() + "\n"
	// Call the production predicate rather than restating it, so this helper
	// cannot drift away from Execute().
	if shouldShowVerboseHint(verbose, passedArgValidation) {
		out += "Hint: re-run with --verbose for more details\n"
	}
	return out
}
