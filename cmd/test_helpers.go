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

// executeWithHint simulates Execute() logic without os.Exit, returning the error output.
// Used for testing the verbose hint behavior.
func executeWithHint(cmd *cobra.Command, args []string) string {
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
