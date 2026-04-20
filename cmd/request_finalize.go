package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newRequestApproveCommand(svc accessRequestService) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approve <requestId>",
		Short: "Approve an access request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if svc == nil {
				bootstrapped, err := bootstrapWorkflowsService()
				if err != nil {
					return err
				}
				svc = bootstrapped
			}
			return runFinalize(cmd, args[0], "APPROVED", svc)
		},
	}

	cmd.Flags().String("reason", "", "Reason for approval")

	return cmd
}

func newRequestRejectCommand(svc accessRequestService) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reject <requestId>",
		Short: "Reject an access request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if svc == nil {
				bootstrapped, err := bootstrapWorkflowsService()
				if err != nil {
					return err
				}
				svc = bootstrapped
			}
			return runFinalize(cmd, args[0], "REJECTED", svc)
		},
	}

	cmd.Flags().String("reason", "", "Reason for rejection")

	return cmd
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
