package cmd

import (
	"errors"
	"fmt"

	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca/models"
	sdkmodels "github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/spf13/cobra"
)

// newEnvCommand creates the env cobra command with the given RunE function.
func newEnvCommand(runFn func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Output AWS credential export statements",
		Long: `Perform elevation and output AWS credential export statements.

Runs the full elevation flow, then prints only shell export statements
suitable for eval. No human-readable messages are printed to stdout.

Usage:
  eval $(grant env --provider aws --target "Account" --role "AdminAccess")
  eval $(grant env --favorite my-aws-fav)
  eval $(grant env --refresh --provider aws)`,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE:          runFn,
	}

	cmd.Flags().StringP("provider", "p", "", "Cloud provider: azure, aws (omit to show all)")
	cmd.Flags().StringP("target", "t", "", "Target name (account, subscription, etc.)")
	cmd.Flags().StringP("role", "r", "", "Role name")
	cmd.Flags().StringP("favorite", "f", "", "Use a saved favorite (see 'grant favorites list')")
	cmd.Flags().Bool("refresh", false, "Bypass eligibility cache and fetch fresh data")

	cmd.MarkFlagsMutuallyExclusive("favorite", "target")
	cmd.MarkFlagsMutuallyExclusive("favorite", "role")

	return cmd
}

// NewEnvCommand creates the production env command.
func NewEnvCommand() *cobra.Command {
	return newEnvCommand(func(cmd *cobra.Command, args []string) error {
		flags := parseElevateFlags(cmd)

		cfg, _, err := config.LoadDefaultWithPath()
		if err != nil {
			return err
		}

		ispAuth, scaService, profile, err := bootstrapSCAService()
		if err != nil {
			return err
		}

		cachedLister := buildCachedLister(cfg, flags.refresh, scaService, nil)

		return runEnvWithDeps(cmd, flags, profile, ispAuth, cachedLister, scaService, &uiSelector{}, cfg)
	})
}

// NewEnvCommandWithDeps creates an env command with injected dependencies for testing.
func NewEnvCommandWithDeps(
	profile *sdkmodels.IdsecProfile,
	authLoader authLoader,
	eligibilityLister eligibilityLister,
	elevateService elevateService,
	selector targetSelector,
	cfg *config.Config,
) *cobra.Command {
	return newEnvCommand(func(cmd *cobra.Command, args []string) error {
		flags := parseElevateFlags(cmd)
		return runEnvWithDeps(cmd, flags, profile, authLoader, eligibilityLister, elevateService, selector, cfg)
	})
}

func runEnvWithDeps(
	cmd *cobra.Command,
	flags *elevateFlags,
	profile *sdkmodels.IdsecProfile,
	authLoader authLoader,
	eligibilityLister eligibilityLister,
	elevateService elevateService,
	selector targetSelector,
	cfg *config.Config,
) error {
	res, err := resolveAndElevate(flags, profile, authLoader, eligibilityLister, elevateService, selector, cfg)
	if err != nil {
		return err
	}

	// Record session timestamp for remaining-time tracking (best-effort)
	recordSessionTimestamp(res.result.SessionID)

	if res.result.AccessCredentials == nil {
		return errors.New("no credentials returned; grant env is only supported for AWS elevations")
	}

	awsCreds, err := models.ParseAWSCredentials(*res.result.AccessCredentials)
	if err != nil {
		return fmt.Errorf("failed to parse access credentials: %w", err)
	}

	if isJSONOutput() {
		return writeJSON(cmd.OutOrStdout(), awsCredentialOutput{
			AccessKeyID:    awsCreds.AccessKeyID,
			SecretAccessKey: awsCreds.SecretAccessKey,
			SessionToken:   awsCreds.SessionToken,
		})
	}

	fmt.Fprintf(cmd.OutOrStdout(), "export AWS_ACCESS_KEY_ID='%s'\n", awsCreds.AccessKeyID)
	fmt.Fprintf(cmd.OutOrStdout(), "export AWS_SECRET_ACCESS_KEY='%s'\n", awsCreds.SecretAccessKey)
	fmt.Fprintf(cmd.OutOrStdout(), "export AWS_SESSION_TOKEN='%s'\n", awsCreds.SessionToken)

	return nil
}
