package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newRequestApproveCommand(svc accessRequestService) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approve [requestId]",
		Short: "Approve an access request",
		Long:  "Approve an access request. If <requestId> is omitted in a terminal, an interactive picker of pending requests assigned to you is shown.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			requestID := ""
			if len(args) > 0 {
				requestID = args[0]
			}
			if err := earlyNonInteractiveCheck(requestID); err != nil {
				return err
			}
			if svc == nil {
				bootstrapped, err := bootstrapWorkflowsService()
				if err != nil {
					return err
				}
				svc = bootstrapped
			}
			id, err := resolveFinalizeRequestID(cmd, args, svc)
			if err != nil {
				return err
			}
			return runFinalize(cmd, id, "APPROVED", svc)
		},
	}

	cmd.Flags().String("reason", "", "Reason for approval")

	return cmd
}

func newRequestRejectCommand(svc accessRequestService) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reject [requestId]",
		Short: "Reject an access request",
		Long:  "Reject an access request. If <requestId> is omitted in a terminal, an interactive picker of pending requests assigned to you is shown.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			requestID := ""
			if len(args) > 0 {
				requestID = args[0]
			}
			if err := earlyNonInteractiveCheck(requestID); err != nil {
				return err
			}
			if svc == nil {
				bootstrapped, err := bootstrapWorkflowsService()
				if err != nil {
					return err
				}
				svc = bootstrapped
			}
			id, err := resolveFinalizeRequestID(cmd, args, svc)
			if err != nil {
				return err
			}
			return runFinalize(cmd, id, "REJECTED", svc)
		},
	}

	cmd.Flags().String("reason", "", "Reason for rejection")

	return cmd
}

// resolveFinalizeRequestID returns the positional requestId, or falls back to
// the interactive picker scoped to approver-pending requests.
func resolveFinalizeRequestID(cmd *cobra.Command, args []string, svc accessRequestService) (string, error) {
	if len(args) > 0 && args[0] != "" {
		return args[0], nil
	}
	return resolveRequestIDFn(cmd.Context(), svc, pickerScope{
		filter:      "(requestState eq PENDING)",
		requestRole: "APPROVER",
		emptyMsg:    "pending requests assigned to you",
	})
}

func runFinalize(cmd *cobra.Command, requestID, decision string, svc accessRequestService) error {
	ctx := cmd.Context()

	var reason *string
	if v, _ := cmd.Flags().GetString("reason"); v != "" {
		reason = &v
	}

	log.Info("Finalizing access request %s with result %s", requestID, decision)

	result, err := svc.FinalizeRequest(ctx, requestID, decision, reason)
	if err != nil {
		return fmt.Errorf("failed to %s request: %w", decisionVerb(decision), err)
	}

	if isJSONOutput() {
		return writeJSON(cmd.OutOrStdout(), toAccessRequestOutput(result))
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Request %s %s.\n", result.RequestID, decisionPastTense(decision))
	fmt.Fprintf(cmd.OutOrStdout(), "Result: %s\n", result.RequestResult)
	return nil
}

func decisionVerb(decision string) string {
	if decision == "APPROVED" {
		return "approve"
	}
	return "reject"
}

func decisionPastTense(decision string) string {
	if decision == "APPROVED" {
		return "approved"
	}
	return "rejected"
}
