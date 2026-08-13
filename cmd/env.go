package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca/models"
	sdkmodels "github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/spf13/cobra"
)

// newEnvCommand creates the env cobra command with the given RunE function.
func newEnvCommand(runFn func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Output AWS credential export statements (AWS only)",
		Long: `Perform an AWS elevation and output credential export statements.

Runs the full elevation flow, then prints only shell export statements
suitable for eval. No human-readable messages are printed to stdout.

Only AWS is supported: Azure and GCP elevations return no credentials —
they apply to your existing az/gcloud CLI session, so use 'grant' instead.

Usage:
  eval $(grant env --provider aws --target "Account" --role "AdminAccess")
  eval $(grant env --favorite my-aws-fav)
  eval $(grant env --refresh --provider aws)`,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE:          runFn,
	}

	cmd.Flags().StringP("provider", "p", "", "Cloud provider (aws only)")
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

// requireAWSTarget rejects non-AWS targets before an elevation is performed.
// An unresolved CSP is allowed through, so the post-elevation credential check
// remains the fallback.
func requireAWSTarget(target *models.EligibleTarget) error {
	if target.CSP == "" || target.CSP == models.CSPAWS {
		return nil
	}
	provider := strings.ToLower(string(target.CSP))
	return fmt.Errorf(
		"grant env is only supported for AWS; %s elevations return no credentials — run 'grant --provider %s' instead and use your existing %s CLI session",
		provider, provider, cliForCSP(target.CSP))
}

// cliForCSP names the native CLI whose session a non-AWS elevation applies to.
func cliForCSP(csp models.CSP) string {
	switch csp {
	case models.CSPAzure:
		return "az"
	case models.CSPGCP:
		return "gcloud"
	default:
		return "cloud provider"
	}
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
	res, err := resolveAndElevate(flags, profile, authLoader, eligibilityLister, elevateService, selector, cfg, requireAWSTarget)
	if err != nil {
		return err
	}

	// Record session timestamp for remaining-time tracking (best-effort)
	recordSessionTimestamp(res.result.SessionID)

	// Defense in depth: AWS itself returning no credentials.
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
