package cmd

import (
	"fmt"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	auth_models "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	"github.com/spf13/cobra"
)

// authenticator is the interface we need for login command
type authenticator interface {
	Authenticate(profile *models.IdsecProfile, authProfile *auth_models.IdsecAuthProfile, secret *auth_models.IdsecSecret, force bool, refreshAuth bool) (*auth_models.IdsecToken, error)
}

// profileLoader is the interface for loading profiles
type profileLoader interface {
	LoadProfile(string) (*models.IdsecProfile, error)
}

// NewLoginCommand creates the login command
func NewLoginCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate to CyberArk SCA",
		Long: `Authenticate to CyberArk Secure Cloud Access (SCA) and cache the authentication token.

If this is your first time using sca-cli, you will be prompted to configure your tenant URL and username.
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
			return runLoginWithAuth(cmd, auth)
		},
	}
}

func runLogin(cmd *cobra.Command, ispAuth auth.IdsecAuth) error {
	// Load the SDK profile
	loader := profiles.DefaultProfilesLoader()
	profile, err := (*loader).LoadProfile("sca-cli")
	if err != nil {
		return fmt.Errorf("failed to load profile: %w", err)
	}

	// If profile doesn't exist, run configure flow
	if profile == nil {
		fmt.Fprintln(cmd.OutOrStdout(), "No configuration found. Let's set up sca-cli.")

		// Run configure interactively
		saver := &profiles.FileSystemProfilesLoader{}
		if err := runConfigure(cmd, saver, "", "", ""); err != nil {
			return err
		}

		// Reload profile after configuration
		profile, err = (*loader).LoadProfile("sca-cli")
		if err != nil {
			return fmt.Errorf("failed to load profile after configuration: %w", err)
		}

		if profile == nil {
			return fmt.Errorf("profile not found after configuration")
		}
	}

	// Authenticate (pass empty secret for interactive auth)
	token, err := ispAuth.Authenticate(profile, nil, &auth_models.IdsecSecret{Secret: ""}, false, true)
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

func runLoginWithAuth(cmd *cobra.Command, auth authenticator) error {
	// Load the SDK profile
	loader := profiles.DefaultProfilesLoader()
	profile, err := (*loader).LoadProfile("sca-cli")
	if err != nil {
		return fmt.Errorf("failed to load profile: %w", err)
	}

	// If profile doesn't exist, run configure flow
	if profile == nil {
		fmt.Fprintln(cmd.OutOrStdout(), "No configuration found. Let's set up sca-cli.")

		// Run configure interactively
		saver := &profiles.FileSystemProfilesLoader{}
		if err := runConfigure(cmd, saver, "", "", ""); err != nil {
			return err
		}

		// Reload profile after configuration
		profile, err = (*loader).LoadProfile("sca-cli")
		if err != nil {
			return fmt.Errorf("failed to load profile after configuration: %w", err)
		}

		if profile == nil {
			return fmt.Errorf("profile not found after configuration")
		}
	}

	// Authenticate (pass empty secret for interactive auth)
	token, err := auth.Authenticate(profile, nil, &auth_models.IdsecSecret{Secret: ""}, false, true)
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

func init() {
	rootCmd.AddCommand(NewLoginCommand())
}
