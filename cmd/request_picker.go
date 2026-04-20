package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/aaearon/grant-cli/internal/ui"
	"github.com/aaearon/grant-cli/internal/workflows"
)

// earlyNonInteractiveCheck fails fast before bootstrap when no requestID is
// provided and stdin is not a TTY.
func earlyNonInteractiveCheck(requestID string) error {
	if requestID == "" && !ui.IsInteractive() {
		return fmt.Errorf("%w; pass the request ID as a positional argument (run `grant request list` to find it)", ui.ErrNotInteractive)
	}
	return nil
}

// pickerScope describes how to scope the list of requests surfaced in the picker.
type pickerScope struct {
	filter      string // OData filter; empty = no filter
	requestRole string // "CREATOR" | "APPROVER" | ""
	emptyMsg    string // e.g. "open requests you created"
}

// resolveRequestIDFn is injectable for testing.
var resolveRequestIDFn = resolveRequestIDInteractive

// resolveRequestIDInteractive fetches a scoped list of access requests and
// shows the interactive picker, returning the chosen request ID.
func resolveRequestIDInteractive(ctx context.Context, svc accessRequestService, scope pickerScope) (string, error) {
	if !ui.IsInteractive() {
		if isJSONOutput() {
			return "", errors.New("request ID is required with --output json; run `grant request list --output json` to find it")
		}
		return "", fmt.Errorf("%w; pass the request ID as a positional argument (run `grant request list` to find it)", ui.ErrNotInteractive)
	}

	items, _, err := svc.ListRequests(ctx, workflows.ListRequestsParams{
		Filter:      scope.filter,
		RequestRole: scope.requestRole,
		Sort:        "createdAt desc",
	})
	if err != nil {
		return "", fmt.Errorf("failed to list requests: %w", err)
	}

	if len(items) == 0 {
		return "", errors.New("no " + scope.emptyMsg + "; nothing to act on")
	}

	chosen, err := ui.SelectRequest(items)
	if err != nil {
		return "", err
	}
	return chosen.RequestID, nil
}
