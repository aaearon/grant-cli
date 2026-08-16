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

// errRevocationIncomplete is returned when the service did not accept
// revocation for every requested session.
//
// Exit policy, precisely. A non-zero exit means at least one requested session
// was refused (REVOCATION_NOT_APPLICABLE), carried an unrecognized status, or
// had no result returned for it at all — unrecognized and missing statuses fail
// closed. A zero exit means every requested session was *accepted*, which
// includes REVOCATION_IN_PROGRESS: the service took the command and will act,
// but has not confirmed the access is gone. That is a documented asynchronous
// success state, so treating it as a failure would make legitimate revocations
// look broken; the per-session breakdown still distinguishes it from a
// confirmed revocation, and `grant status` shows what is still live.
var errRevocationIncomplete = errors.New("not all requested sessions were revoked")

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
	cmd.Flags().StringP("provider", "p", "", "filter sessions by provider (azure, aws, gcp)")

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

		cachedLister, err := buildCachedLister(cfg, false, svc, nil)
		if err != nil {
			return err
		}

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

	// Determine which sessions to revoke.
	sessionIDs, done, err := resolveRevokeTargets(cmd, args, lister, elig, selector, confirmer, cspFilter, allFlag, yesFlag)
	if err != nil || done {
		return err
	}

	// The requested set is the source of truth for every count and for the exit
	// code, so deduplicate it before sending and before reconciling.
	sessionIDs = dedupeSessionIDs(sessionIDs)

	// A failing batch still returns the results already collected.
	results, revokeErr := revokeInBatches(context.Background(), revoker, sessionIDs)

	records, unattached := reconcileRevocations(sessionIDs, results)

	if isJSONOutput() {
		if err := writeJSON(cmd.OutOrStdout(), buildRevocationJSON(records, unattached)); err != nil {
			return err
		}
	} else {
		// Always print the full breakdown before returning an error, so a
		// non-zero exit is never opaque.
		renderRevocationResults(cmd.OutOrStdout(), records, unattached)
	}

	if revokeErr != nil {
		return revokeErr
	}

	if summary := summarizeRevocations(records); !summary.allAccepted() {
		return fmt.Errorf("%w: %s", errRevocationIncomplete, summaryLine(summary))
	}

	return nil
}

// resolveRevokeTargets determines the session IDs to revoke. done reports that
// the command has already finished (nothing to revoke, or the user declined).
func resolveRevokeTargets(
	cmd *cobra.Command,
	args []string,
	lister sessionLister,
	elig eligibilityLister,
	selector sessionSelector,
	confirmer confirmPrompter,
	cspFilter *scamodels.CSP,
	allFlag, yesFlag bool,
) (sessionIDs []string, done bool, err error) {
	if len(args) > 0 {
		// Direct mode: session IDs provided as arguments.
		return args, false, nil
	}

	// All or interactive mode: list sessions first.
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	sessions, err := lister.ListSessions(ctx, cspFilter)
	if err != nil {
		return nil, true, fmt.Errorf("failed to list sessions: %w", err)
	}

	if len(sessions.Response) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No active sessions to revoke.")
		return nil, true, nil
	}

	selected := sessions.Response
	if !allFlag {
		nameMap := buildWorkspaceNameMap(ctx, elig, sessions.Response)
		selected, err = selector.SelectSessions(sessions.Response, nameMap)
		if err != nil {
			return nil, true, fmt.Errorf("session selection failed: %w", err)
		}
		// Selecting nothing is a deliberate no-op, equivalent to declining the
		// confirmation. Handled here rather than after the request is built, so
		// an empty selection can never be revoked as if it were a request.
		if len(selected) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No sessions selected.")
			return nil, true, nil
		}
	}

	for _, s := range selected {
		sessionIDs = append(sessionIDs, s.SessionID)
	}

	if !yesFlag {
		confirmed, cerr := confirmer.ConfirmRevocation(len(sessionIDs))
		if cerr != nil {
			return nil, true, fmt.Errorf("confirmation failed: %w", cerr)
		}
		if !confirmed {
			fmt.Fprintln(cmd.OutOrStdout(), "Revocation canceled.")
			return nil, true, nil
		}
	}

	return sessionIDs, false, nil
}
