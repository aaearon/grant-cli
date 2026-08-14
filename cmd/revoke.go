package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aaearon/grant-cli/internal/cache"
	"github.com/aaearon/grant-cli/internal/config"
	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/aaearon/grant-cli/internal/ui"
	sdkmodels "github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/spf13/cobra"
)

// errRevocationIncomplete is returned when at least one requested session was
// not accepted for revocation. grant fails closed: a security-remediation
// command must not exit 0 while access may still be live.
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

		cachedLister := buildCachedLister(cfg, false, svc, nil)

		// Session timestamp tracker for the best-effort expiry note (may be nil).
		var tracker *cache.Store
		if cacheDir, err := cache.CacheDir(); err == nil {
			tracker = cache.NewStore(cacheDir, 25*time.Hour)
		}

		return runRevoke(cmd, args, ispAuth, svc, cachedLister, svc, &uiSessionSelector{}, &uiConfirmPrompter{}, profile, tracker, time.Now)
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
	return newRevokeCommandWithClock(auth, lister, elig, revoker, selector, confirmer, nil, time.Now)
}

// newRevokeCommandWithClock is NewRevokeCommandWithDeps plus a session
// timestamp tracker and an injectable clock, so expiry notes are deterministic
// in tests.
func newRevokeCommandWithClock(
	auth authLoader,
	lister sessionLister,
	elig eligibilityLister,
	revoker sessionRevoker,
	selector sessionSelector,
	confirmer confirmPrompter,
	tracker *cache.Store,
	now func() time.Time,
) *cobra.Command {
	return newRevokeCommand(func(cmd *cobra.Command, args []string) error {
		return runRevoke(cmd, args, auth, lister, elig, revoker, selector, confirmer, nil, tracker, now)
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
	tracker *cache.Store,
	now func() time.Time,
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

	// Determine which sessions to revoke. metadata stays empty in direct mode,
	// where grant only has bare session IDs.
	sessionIDs, metadata, done, err := resolveRevokeTargets(cmd, args, lister, elig, selector, confirmer, cspFilter, allFlag, yesFlag)
	if err != nil || done {
		return err
	}

	// The requested set is the source of truth for every count and for the exit
	// code, so deduplicate it before sending and before reconciling.
	sessionIDs = dedupeSessionIDs(sessionIDs)
	if len(sessionIDs) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No sessions selected.")
		return nil
	}

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
		renderRevocationResults(cmd.OutOrStdout(), records, unattached, expiryHinter{
			metadata:   metadata,
			timestamps: sessionTimestamps(tracker),
			now:        now,
		})
	}

	if revokeErr != nil {
		return revokeErr
	}

	if summary := summarizeRevocations(records); !summary.allAccepted() {
		return fmt.Errorf("%w: %s", errRevocationIncomplete, summaryLine(summary))
	}

	return nil
}

// sessionTimestamps reads local elevation timestamps, tolerating a nil tracker.
func sessionTimestamps(tracker *cache.Store) map[string]time.Time {
	if tracker == nil {
		return nil
	}
	return cache.SessionTimestamps(tracker)
}

// resolveRevokeTargets determines the session IDs to revoke, along with session
// metadata when grant listed the sessions itself. done reports that the command
// has already finished (nothing to revoke, or the user declined).
func resolveRevokeTargets(
	cmd *cobra.Command,
	args []string,
	lister sessionLister,
	elig eligibilityLister,
	selector sessionSelector,
	confirmer confirmPrompter,
	cspFilter *scamodels.CSP,
	allFlag, yesFlag bool,
) (sessionIDs []string, metadata map[string]scamodels.SessionInfo, done bool, err error) {
	if len(args) > 0 {
		// Direct mode: session IDs provided as arguments, no metadata available.
		return args, nil, false, nil
	}

	// All or interactive mode: list sessions first.
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	sessions, err := lister.ListSessions(ctx, cspFilter)
	if err != nil {
		return nil, nil, true, fmt.Errorf("failed to list sessions: %w", err)
	}

	if len(sessions.Response) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No active sessions to revoke.")
		return nil, nil, true, nil
	}

	metadata = make(map[string]scamodels.SessionInfo, len(sessions.Response))
	for _, s := range sessions.Response {
		metadata[s.SessionID] = s
	}

	selected := sessions.Response
	if !allFlag {
		nameMap := buildWorkspaceNameMap(ctx, elig, sessions.Response)
		selected, err = selector.SelectSessions(sessions.Response, nameMap)
		if err != nil {
			return nil, nil, true, fmt.Errorf("session selection failed: %w", err)
		}
	}

	for _, s := range selected {
		sessionIDs = append(sessionIDs, s.SessionID)
	}

	if !yesFlag {
		confirmed, cerr := confirmer.ConfirmRevocation(len(sessionIDs))
		if cerr != nil {
			return nil, nil, true, fmt.Errorf("confirmation failed: %w", cerr)
		}
		if !confirmed {
			fmt.Fprintln(cmd.OutOrStdout(), "Revocation canceled.")
			return nil, nil, true, nil
		}
	}

	return sessionIDs, metadata, false, nil
}
