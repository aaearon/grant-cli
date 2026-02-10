package cmd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aaearon/sca-cli/internal/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	auth_models "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	survey "github.com/Iilun/survey/v2"
	"github.com/spf13/cobra"
)

// profileSaver interface for dependency injection
type profileSaver interface {
	SaveProfile(profile *models.IdsecProfile) error
}

var (
	validMFAMethods = []string{"otp", "oath", "sms", "email", "pf"}
)

// NewConfigureCommand creates the configure command
func NewConfigureCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Configure sca-cli with CyberArk tenant credentials",
		Long: `Configure sca-cli by providing your CyberArk tenant URL, username, and optional MFA method.

This command creates two configuration files:
- SDK profile at ~/.idsec_profiles/sca-cli.json
- App config at ~/.sca-cli/config.yaml

The configuration is stored locally and used for authentication.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Use the default file system profile loader
			loader := &profiles.FileSystemProfilesLoader{}
			return runConfigure(cmd, loader, "", "", "")
		},
	}

	return cmd
}

// NewConfigureCommandWithDeps creates a configure command with injected dependencies for testing
func NewConfigureCommandWithDeps(saver profileSaver, tenantURL, username, mfaMethod string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Configure sca-cli with CyberArk tenant credentials",
		Long:  "Configure sca-cli by providing your CyberArk tenant URL, username, and optional MFA method.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigure(cmd, saver, tenantURL, username, mfaMethod)
		},
	}

	return cmd
}

func runConfigure(cmd *cobra.Command, saver profileSaver, tenantURL, username, mfaMethod string) error {
	// Only prompt if values are not provided (interactive mode only when all are empty)
	promptNeeded := tenantURL == "" && username == "" && mfaMethod == ""

	if promptNeeded {
		if err := survey.AskOne(&survey.Input{
			Message: "CyberArk Tenant URL:",
			Help:    "The full URL of your CyberArk tenant (e.g., https://example.cyberark.cloud)",
		}, &tenantURL, survey.WithValidator(survey.Required)); err != nil {
			return fmt.Errorf("failed to read tenant URL: %w", err)
		}

		if err := survey.AskOne(&survey.Input{
			Message: "Username:",
			Help:    "Your CyberArk username or email",
		}, &username, survey.WithValidator(survey.Required)); err != nil {
			return fmt.Errorf("failed to read username: %w", err)
		}

		// Prompt for MFA method, allow blank
		if err := survey.AskOne(&survey.Input{
			Message: "MFA Method (optional):",
			Help:    "Leave blank for interactive selection, or specify: otp, oath, sms, email, pf",
		}, &mfaMethod); err != nil {
			return fmt.Errorf("failed to read MFA method: %w", err)
		}
	}

	// Validate inputs
	if err := validateTenantURL(tenantURL); err != nil {
		return err
	}

	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("username is required")
	}

	if err := validateMFAMethod(mfaMethod); err != nil {
		return err
	}

	// Create SDK profile
	profile := &models.IdsecProfile{
		ProfileName:        "sca-cli",
		ProfileDescription: "SCA CLI Profile",
		AuthProfiles: map[string]*auth_models.IdsecAuthProfile{
			"isp": {
				Username:   username,
				AuthMethod: auth_models.Identity,
				AuthMethodSettings: &auth_models.IdentityIdsecAuthMethodSettings{
					IdentityURL:            tenantURL,
					IdentityMFAMethod:      mfaMethod,
					IdentityMFAInteractive: true,
				},
			},
		},
	}

	// Save SDK profile
	if err := saver.SaveProfile(profile); err != nil {
		return fmt.Errorf("failed to save profile: %w", err)
	}

	// Get profile directory for success message
	profileDir := os.Getenv("IDSEC_PROFILES_FOLDER")
	if profileDir == "" {
		home, _ := os.UserHomeDir()
		profileDir = filepath.Join(home, ".idsec_profiles")
	}
	profilePath := filepath.Join(profileDir, "sca-cli.json")

	// Create app config
	cfg := &config.Config{
		Profile:         "sca-cli",
		DefaultProvider: "azure",
		Favorites:       make(map[string]config.Favorite),
	}

	// Save app config
	cfgPath := config.ConfigPath()
	if err := config.Save(cfg, cfgPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	// Success message
	cmd.Printf("Profile saved to %s\n", profilePath)
	cmd.Printf("Config saved to %s\n", cfgPath)

	return nil
}

// validateTenantURL validates that the tenant URL is a valid HTTPS URL
func validateTenantURL(tenantURL string) error {
	if strings.TrimSpace(tenantURL) == "" {
		return fmt.Errorf("invalid tenant URL: cannot be empty")
	}

	u, err := url.Parse(tenantURL)
	if err != nil {
		return fmt.Errorf("invalid tenant URL: %w", err)
	}

	if u.Scheme != "https" {
		return fmt.Errorf("invalid tenant URL: must use HTTPS scheme")
	}

	if u.Host == "" {
		return fmt.Errorf("invalid tenant URL: must have a host")
	}

	return nil
}

// validateMFAMethod validates that the MFA method is one of the allowed values or empty
func validateMFAMethod(method string) error {
	method = strings.TrimSpace(method)

	// Empty is valid (interactive selection)
	if method == "" {
		return nil
	}

	// Check if method is in the valid list
	for _, valid := range validMFAMethods {
		if method == valid {
			return nil
		}
	}

	return fmt.Errorf("invalid MFA method %q: must be one of: %s", method, strings.Join(validMFAMethods, ", "))
}

func init() {
	rootCmd.AddCommand(NewConfigureCommand())
}
