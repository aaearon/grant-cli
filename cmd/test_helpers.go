// NOTE: Do not use t.Parallel() in cmd/ tests due to package-level state
// (verbose, passedArgValidation) that is mutated during test execution.
package cmd

import (
	"bytes"

	"github.com/spf13/cobra"
)

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
	if !verbose && passedArgValidation {
		out += "Hint: re-run with --verbose for more details\n"
	}
	return out
}
