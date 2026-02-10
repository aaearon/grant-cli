package cmd

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/spf13/cobra"
)

var verbose bool

var rootCmd = &cobra.Command{
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

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if !verbose {
			fmt.Fprintln(os.Stderr, "Hint: re-run with --verbose for more details")
		}
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
}
