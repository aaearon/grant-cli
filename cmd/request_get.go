package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

func newRequestGetCommand(svc accessRequestService) *cobra.Command {
	return &cobra.Command{
		Use:   "get [requestId]",
		Short: "Get details of an access request",
		Long:  "Get details of an access request. If <requestId> is omitted in a terminal, an interactive picker of your access requests is shown.",
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
					emptyMsg: "access requests",
				})
				if err != nil {
					return err
				}
				requestID = id
			}
			return runRequestGet(cmd, requestID, svc)
		},
	}
}

func runRequestGet(cmd *cobra.Command, requestID string, svc accessRequestService) error {
	if requestID == "" {
		return errors.New("request ID is required")
	}

	ctx := cmd.Context()
	log.Info("Getting access request %s", requestID)

	result, err := svc.GetRequest(ctx, requestID)
	if err != nil {
		return fmt.Errorf("failed to get request: %w", err)
	}

	if isJSONOutput() {
		return writeJSON(cmd.OutOrStdout(), toAccessRequestOutput(result))
	}

	formatRequestDetail(cmd, result)
	return nil
}
