package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newRequestCancelCommand(svc accessRequestService) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cancel [requestId]",
		Short: "Cancel an open access request",
		Long:  "Cancel an open access request. If <requestId> is omitted in a terminal, an interactive picker of open requests you created is shown.",
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
			if requestID == "" {
				id, err := resolveRequestIDFn(cmd.Context(), svc, pickerScope{
					filter:      "((requestState eq STARTING) or (requestState eq RUNNING) or (requestState eq PENDING))",
					requestRole: "CREATOR",
					emptyMsg:    "open requests you created",
				})
				if err != nil {
					return err
				}
				requestID = id
			}
			return runRequestCancel(cmd, requestID, svc)
		},
	}

	cmd.Flags().String("reason", "", "Reason for cancellation")

	return cmd
}

func runRequestCancel(cmd *cobra.Command, requestID string, svc accessRequestService) error {
	ctx := cmd.Context()

	var reason *string
	if v, _ := cmd.Flags().GetString("reason"); v != "" {
		reason = &v
	}

	log.Info("Canceling access request %s", requestID)

	result, err := svc.CancelRequest(ctx, requestID, reason)
	if err != nil {
		return fmt.Errorf("failed to cancel request: %w", err)
	}

	if isJSONOutput() {
		return writeJSON(cmd.OutOrStdout(), toAccessRequestOutput(result))
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Request %s canceled.\n", result.RequestID)
	fmt.Fprintf(cmd.OutOrStdout(), "Result: %s\n", result.RequestResult)
	return nil
}
