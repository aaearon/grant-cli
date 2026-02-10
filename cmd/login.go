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

// NewLoginCommand creates the login command
func NewLoginCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate to CyberArk SCA",
		Long:  "Authenticate to CyberArk Secure Cloud Access (SCA) and cache the authentication token.",
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

	// Authenticate
	token, err := ispAuth.Authenticate(profile, nil, nil, false, true)
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

	// Authenticate
	token, err := auth.Authenticate(profile, nil, nil, false, true)
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
