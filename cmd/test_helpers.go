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
	defer restoreOutputFormat(outputFormat)

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

// restoreOutputFormat puts the package-global outputFormat back. Cobra binds
// --output to that global with StringVarP, so executing any command that
// carries the flag leaves the global set for every later test. A command built
// without the root flag set (NewEnvCommandWithDeps, for instance) then inherits
// "json" from whichever test ran before it — an order dependence that only
// shows up under `go test -shuffle=on`.
func restoreOutputFormat(saved string) { outputFormat = saved }

// executeCommandStreams executes a command keeping stdout and stderr apart and
// writing no error text into either. Use it when a test needs to assert on the
// exact stdout payload (e.g. valid JSON) *and* on a returned error, which
// executeCommand cannot express because it merges the streams and appends the
// error text.
func executeCommandStreams(cmd *cobra.Command, args ...string) (stdout, stderr string, err error) {
	defer restoreOutputFormat(outputFormat)

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
	defer restoreOutputFormat(outputFormat)

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
