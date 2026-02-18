package cmd

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/common/keyring"
	"github.com/spf13/cobra"
)

// NewLogoutCommand creates the logout command
func NewLogoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out and clear cached authentication tokens",
		Long:  "Log out of grant by clearing cached authentication tokens from the system keyring.",
		RunE: func(cmd *cobra.Command, args []string) error {
			kr, err := keyring.NewIdsecKeyring("grant").GetKeyring(true)
			if err != nil {
				return fmt.Errorf("failed to access keyring: %w", err)
			}
			return runLogout(cmd, kr)
		},
	}
}

// NewLogoutCommandWithDeps creates a logout command with injected dependencies for testing
func NewLogoutCommandWithDeps(clearer keyringClearer) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out and clear cached authentication tokens",
		Long:  "Log out of grant by clearing cached authentication tokens from the system keyring.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogout(cmd, clearer)
		},
	}
}

func runLogout(cmd *cobra.Command, clearer keyringClearer) error {
	if err := clearer.ClearAllPasswords(); err != nil {
		return fmt.Errorf("failed to clear authentication: %w", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Logged out successfully")
	return nil
}
