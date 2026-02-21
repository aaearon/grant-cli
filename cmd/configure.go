package cmd

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aaearon/grant-cli/internal/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	survey "github.com/Iilun/survey/v2"
	"github.com/spf13/cobra"
)

// NewConfigureCommand creates the configure command
func NewConfigureCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Configure grant with CyberArk Identity credentials",
		Long: `Configure grant by providing your CyberArk username and optional Identity URL.

This command creates two configuration files:
- SDK profile at ~/.idsec_profiles/grant
- App config at ~/.grant/config.yaml

The Identity URL is optional — the SDK can auto-discover it from your username.
If provided, it must be HTTPS (e.g., https://abc1234.id.cyberark.cloud).

The configuration is stored locally and used for authentication.
MFA method selection is handled interactively during login.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Use the default file system profile loader
			loader := &profiles.FileSystemProfilesLoader{}
			return runConfigure(cmd, loader, "", "")
		},
	}

	return cmd
}

// NewConfigureCommandWithDeps creates a configure command with injected dependencies for testing
func NewConfigureCommandWithDeps(saver profileSaver, tenantURL, username string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Configure grant with CyberArk tenant credentials",
		Long:  "Configure grant by providing your CyberArk tenant URL and username.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigure(cmd, saver, tenantURL, username)
		},
	}

	return cmd
}

func runConfigure(cmd *cobra.Command, saver profileSaver, tenantURL, username string) error {
	// Only prompt if username is not provided
	promptNeeded := username == ""

	if promptNeeded {
		if err := survey.AskOne(&survey.Input{
			Message: "Username:",
			Help:    "Your CyberArk username or email",
		}, &username, survey.WithValidator(survey.Required)); err != nil {
			return fmt.Errorf("failed to read username: %w", err)
		}

		if err := survey.AskOne(&survey.Input{
			Message: "CyberArk Identity URL (optional):",
			Help:    "Leave blank to auto-detect from username (e.g., https://abc1234.id.cyberark.cloud)",
		}, &tenantURL); err != nil {
			return fmt.Errorf("failed to read tenant URL: %w", err)
		}
	}

	// Validate inputs
	if strings.TrimSpace(tenantURL) != "" {
		if err := validateTenantURL(tenantURL); err != nil {
			return err
		}
	}

	if strings.TrimSpace(username) == "" {
		return errors.New("username is required")
	}

	// Create SDK profile
	profile := &models.IdsecProfile{
		ProfileName:        "grant",
		ProfileDescription: "SCA CLI Profile",
		AuthProfiles: map[string]*authmodels.IdsecAuthProfile{
			"isp": {
				Username:   username,
				AuthMethod: authmodels.Identity,
				AuthMethodSettings: &authmodels.IdentityIdsecAuthMethodSettings{
					IdentityURL:            tenantURL,
					IdentityMFAMethod:      "", // Always empty - SDK handles MFA interactively
					IdentityMFAInteractive: true,
				},
			},
		},
	}

	// Save SDK profile
	log.Info("Saving profile...")
	if err := saver.SaveProfile(profile); err != nil {
		return fmt.Errorf("failed to save profile: %w", err)
	}

	// Get profile directory for success message
	profileDir := os.Getenv("IDSEC_PROFILES_FOLDER")
	if profileDir == "" {
		home, _ := os.UserHomeDir()
		profileDir = filepath.Join(home, ".idsec_profiles")
	}
	profilePath := filepath.Join(profileDir, "grant")

	// Create app config
	cfg := &config.Config{
		Profile:         "grant",
		DefaultProvider: "azure",
		Favorites:       make(map[string]config.Favorite),
	}

	// Save app config
	log.Info("Saving config...")
	cfgPath, err := config.ConfigPath()
	if err != nil {
		return err
	}
	if err := config.Save(cfg, cfgPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	// Success message
	fmt.Fprintf(cmd.OutOrStdout(), "Profile saved to %s\n", profilePath)
	fmt.Fprintf(cmd.OutOrStdout(), "Config saved to %s\n", cfgPath)

	return nil
}

// validateTenantURL validates that the tenant URL is a valid HTTPS URL
func validateTenantURL(tenantURL string) error {
	if strings.TrimSpace(tenantURL) == "" {
		return errors.New("invalid tenant URL: cannot be empty")
	}

	u, err := url.Parse(tenantURL)
	if err != nil {
		return fmt.Errorf("invalid tenant URL: %w", err)
	}

	if u.Scheme != "https" {
		return errors.New("invalid tenant URL: must use HTTPS scheme")
	}

	if u.Host == "" {
		return errors.New("invalid tenant URL: must have a host")
	}

	return nil
}
