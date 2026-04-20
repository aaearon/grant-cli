package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

func newRequestGetCommand(svc accessRequestService) *cobra.Command {
	return &cobra.Command{
		Use:   "get <requestId>",
		Short: "Get details of an access request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if svc == nil {
				bootstrapped, err := bootstrapWorkflowsService()
				if err != nil {
					return err
				}
				svc = bootstrapped
			}
			return runRequestGet(cmd, args[0], svc)
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
