package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version   = ""
	commit    = ""
	buildDate = ""
)

// NewVersionCommand creates the version command
func NewVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long:  "Print the version, commit hash, and build date of grant",
		RunE: func(cmd *cobra.Command, args []string) error {
			return printVersion(cmd)
		},
	}
}

func printVersion(cmd *cobra.Command) error {
	v := version
	if v == "" {
		v = "dev"
	}

	c := commit
	if c == "" {
		c = "unknown"
	}

	d := buildDate
	if d == "" {
		d = "unknown"
	}

	fmt.Fprintf(cmd.OutOrStdout(), "grant version %s\ncommit: %s\nbuilt: %s\n", v, c, d)
	return nil
}
