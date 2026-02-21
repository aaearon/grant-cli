package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/aaearon/grant-cli/internal/config"
	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/aaearon/grant-cli/internal/ui"
	sdkmodels "github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/spf13/cobra"
)

// uiSessionSelector wraps ui.SelectSessions to implement sessionSelector
type uiSessionSelector struct{}

func (s *uiSessionSelector) SelectSessions(sessions []scamodels.SessionInfo, nameMap map[string]string) ([]scamodels.SessionInfo, error) {
	return ui.SelectSessions(sessions, nameMap)
}

// uiConfirmPrompter wraps ui.ConfirmRevocation to implement confirmPrompter
type uiConfirmPrompter struct{}

func (p *uiConfirmPrompter) ConfirmRevocation(count int) (bool, error) {
	return ui.ConfirmRevocation(count)
}

// newRevokeCommand creates the revoke cobra command with the given RunE function.
func newRevokeCommand(runFn func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke [session-id...]",
		Short: "Revoke active elevated sessions",
		Long: `Revoke one or more active elevated sessions.

Three execution modes:
1. Direct mode: grant revoke <session-id> [<session-id>...]
2. All mode: grant revoke --all [--provider azure]
3. Interactive mode: grant revoke (multi-select prompt)

Use 'grant status' to view session IDs.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE:          runFn,
	}

	cmd.Flags().BoolP("all", "a", false, "revoke all active sessions")
	cmd.Flags().BoolP("yes", "y", false, "skip confirmation prompt")
	cmd.Flags().StringP("provider", "p", "", "filter sessions by provider (azure, aws)")

	return cmd
}

// NewRevokeCommand creates the production revoke command.
func NewRevokeCommand() *cobra.Command {
	return newRevokeCommand(func(cmd *cobra.Command, args []string) error {
		ispAuth, svc, profile, err := bootstrapSCAService()
		if err != nil {
			return err
		}

		cfg, _, err := config.LoadDefaultWithPath()
		if err != nil {
			return err
		}

		cachedLister := buildCachedLister(cfg, false, svc, nil)

		return runRevoke(cmd, args, ispAuth, svc, cachedLister, svc, &uiSessionSelector{}, &uiConfirmPrompter{}, profile)
	})
}

// NewRevokeCommandWithDeps creates a revoke command with injected dependencies for testing.
func NewRevokeCommandWithDeps(
	auth authLoader,
	lister sessionLister,
	elig eligibilityLister,
	revoker sessionRevoker,
	selector sessionSelector,
	confirmer confirmPrompter,
) *cobra.Command {
	return newRevokeCommand(func(cmd *cobra.Command, args []string) error {
		return runRevoke(cmd, args, auth, lister, elig, revoker, selector, confirmer, nil)
	})
}

func runRevoke(
	cmd *cobra.Command,
	args []string,
	auth authLoader,
	lister sessionLister,
	elig eligibilityLister,
	revoker sessionRevoker,
	selector sessionSelector,
	confirmer confirmPrompter,
	profile *sdkmodels.IdsecProfile,
) error {
	allFlag, _ := cmd.Flags().GetBool("all")
	yesFlag, _ := cmd.Flags().GetBool("yes")
	provider, _ := cmd.Flags().GetString("provider")

	// Validate mutual exclusivity
	if allFlag && len(args) > 0 {
		return errors.New("--all cannot be used with session ID arguments")
	}
	if len(args) > 0 && provider != "" {
		return errors.New("--provider cannot be used with session ID arguments")
	}

	// Validate provider
	var cspFilter *scamodels.CSP
	if provider != "" {
		csp, err := parseProvider(provider)
		if err != nil {
			return err
		}
		cspFilter = &csp
	}

	// Check authentication
	_, err := auth.LoadAuthentication(profile, true)
	if err != nil {
		return fmt.Errorf("not authenticated, run 'grant login' first: %w", err)
	}

	// Determine session IDs to revoke
	var sessionIDs []string

	if len(args) > 0 {
		// Direct mode: session IDs provided as arguments
		sessionIDs = args
	} else {
		// All or interactive mode: need to list sessions first
		ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
		defer cancel()

		sessions, err := lister.ListSessions(ctx, cspFilter)
		if err != nil {
			return fmt.Errorf("failed to list sessions: %w", err)
		}

		if len(sessions.Response) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No active sessions to revoke.")
			return nil
		}

		if allFlag {
			// Collect all session IDs
			for _, s := range sessions.Response {
				sessionIDs = append(sessionIDs, s.SessionID)
			}

			// Confirm unless --yes
			if !yesFlag {
				confirmed, err := confirmer.ConfirmRevocation(len(sessionIDs))
				if err != nil {
					return fmt.Errorf("confirmation failed: %w", err)
				}
				if !confirmed {
					fmt.Fprintln(cmd.OutOrStdout(), "Revocation canceled.")
					return nil
				}
			}
		} else {
			// Interactive mode
			nameMap := buildWorkspaceNameMap(ctx, elig, sessions.Response)

			selected, err := selector.SelectSessions(sessions.Response, nameMap)
			if err != nil {
				return fmt.Errorf("session selection failed: %w", err)
			}

			for _, s := range selected {
				sessionIDs = append(sessionIDs, s.SessionID)
			}

			// Confirm
			if !yesFlag {
				confirmed, err := confirmer.ConfirmRevocation(len(sessionIDs))
				if err != nil {
					return fmt.Errorf("confirmation failed: %w", err)
				}
				if !confirmed {
					fmt.Fprintln(cmd.OutOrStdout(), "Revocation canceled.")
					return nil
				}
			}
		}
	}

	// Call revoke API
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	result, err := revoker.RevokeSessions(ctx, &scamodels.RevokeRequest{
		SessionIDs: sessionIDs,
	})
	if err != nil {
		return err
	}

	// Display results
	for _, r := range result.Response {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s: %s\n", r.SessionID, r.RevocationStatus)
	}

	return nil
}
