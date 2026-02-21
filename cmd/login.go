package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	"github.com/spf13/cobra"
)

// NewLoginCommand creates the login command
func NewLoginCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate to CyberArk SCA",
		Long: `Authenticate to CyberArk Secure Cloud Access (SCA) and cache the authentication token.

If this is your first time using grant, you will be prompted to configure your tenant URL and username.
The MFA method will be selected interactively during authentication.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ispAuth := auth.NewIdsecISPAuth(true)
			return runLogin(cmd, ispAuth)
		},
	}
}

// NewLoginCommandWithAuth creates a login command with a custom authenticator for testing
func NewLoginCommandWithAuth(auth authenticator) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate to CyberArk SCA",
		Long:  "Authenticate to CyberArk Secure Cloud Access (SCA) and cache the authentication token.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogin(cmd, auth)
		},
	}
}

func runLogin(cmd *cobra.Command, auth authenticator) error {
	// Load the SDK profile
	log.Info("Loading profile...")
	loader := profiles.DefaultProfilesLoader()
	profile, err := (*loader).LoadProfile("grant")
	if err != nil {
		return fmt.Errorf("failed to load profile: %w", err)
	}

	// If profile doesn't exist, run configure flow
	if profile == nil {
		fmt.Fprintln(cmd.OutOrStdout(), "No configuration found. Let's set up grant.")

		// Run configure interactively
		saver := &profiles.FileSystemProfilesLoader{}
		if err := runConfigure(cmd, saver, "", ""); err != nil {
			return err
		}

		// Reload profile after configuration
		profile, err = (*loader).LoadProfile("grant")
		if err != nil {
			return fmt.Errorf("failed to load profile after configuration: %w", err)
		}

		if profile == nil {
			return errors.New("profile not found after configuration")
		}
	}

	// Authenticate (pass empty secret for interactive auth)
	log.Info("Authenticating...")
	token, err := auth.Authenticate(profile, nil, &authmodels.IdsecSecret{Secret: ""}, false, true)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Display success message
	fmt.Fprintf(cmd.OutOrStdout(), "Successfully authenticated as %s\n", token.Username)

	// Display token expiry if available
	expiresAt := time.Time(token.ExpiresIn)
	if !expiresAt.IsZero() {
		fmt.Fprintf(cmd.OutOrStdout(), "Token expires at %s\n", expiresAt.Format("2006-01-02 15:04:05 MST"))
	}

	return nil
}
