package cmd

import (
	"bytes"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/spf13/cobra"
)

// NewRootCommand creates a new root command for testing
func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sca-cli",
		Short: "Elevate Azure permissions via CyberArk Secure Cloud Access",
		Long:  "sca-cli enables terminal-based Azure permission elevation through CyberArk Secure Cloud Access (SCA).",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				config.EnableVerboseLogging("INFO")
			} else {
				config.DisableVerboseLogging()
			}
			return nil
		},
	}
	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	return cmd
}

// newNoOpCommand creates a minimal command for testing PersistentPreRunE
func newNoOpCommand() *cobra.Command {
	return &cobra.Command{
		Use:  "noop",
		RunE: func(cmd *cobra.Command, args []string) error { return nil },
	}
}

// executeCommand executes a command and returns its output
func executeCommand(cmd *cobra.Command, args ...string) (string, error) {
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)

	err := cmd.Execute()
	return buf.String(), err
}
