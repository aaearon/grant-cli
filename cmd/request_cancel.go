package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newRequestCancelCommand(svc accessRequestService) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cancel <requestId>",
		Short: "Cancel an open access request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if svc == nil {
				bootstrapped, err := bootstrapWorkflowsService()
				if err != nil {
					return err
				}
				svc = bootstrapped
			}
			return runRequestCancel(cmd, args[0], svc)
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
