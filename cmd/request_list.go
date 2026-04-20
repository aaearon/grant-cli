package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aaearon/grant-cli/internal/workflows"
	"github.com/spf13/cobra"
)

func newRequestListCommand(svc accessRequestService) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List access requests",
		Long:  "Retrieve a list of access requests with optional filtering, sorting, and pagination.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if svc == nil {
				bootstrapped, err := bootstrapWorkflowsService()
				if err != nil {
					return err
				}
				svc = bootstrapped
			}
			return runRequestList(cmd, svc)
		},
	}

	cmd.Flags().String("state", "", "Filter by state: STARTING, RUNNING, PENDING, FINISHED, EXPIRED")
	cmd.Flags().String("result", "", "Filter by result: APPROVED, REJECTED, CANCELED, FAILED, UNKNOWN")
	cmd.Flags().String("priority", "", "Filter by priority: High, Medium, Low")
	cmd.Flags().String("role", "", "Request role: CREATOR, APPROVER")
	cmd.Flags().String("search", "", "Free text search")
	cmd.Flags().String("sort", "createdAt", "Sort field: createdAt, updatedAt, calculatedRequestStartTime")
	cmd.Flags().Bool("desc", true, "Sort descending")

	return cmd
}

var (
	validStates     = map[string]bool{"STARTING": true, "RUNNING": true, "PENDING": true, "FINISHED": true, "EXPIRED": true}
	validResults    = map[string]bool{"APPROVED": true, "REJECTED": true, "CANCELED": true, "FAILED": true, "UNKNOWN": true}
	validPriorities = map[string]bool{"High": true, "Medium": true, "Low": true}
	validSorts      = map[string]bool{"createdAt": true, "updatedAt": true, "calculatedRequestStartTime": true}
)

func runRequestList(cmd *cobra.Command, svc accessRequestService) error {
	ctx := cmd.Context()

	params := workflows.ListRequestsParams{}

	var filters []string
	if v, _ := cmd.Flags().GetString("state"); v != "" {
		upper := strings.ToUpper(v)
		if !validStates[upper] {
			return fmt.Errorf("--state must be one of STARTING, RUNNING, PENDING, FINISHED, EXPIRED (got %q)", v)
		}
		filters = append(filters, fmt.Sprintf("(requestState eq %s)", upper))
	}
	if v, _ := cmd.Flags().GetString("result"); v != "" {
		upper := strings.ToUpper(v)
		if !validResults[upper] {
			return fmt.Errorf("--result must be one of APPROVED, REJECTED, CANCELED, FAILED, UNKNOWN (got %q)", v)
		}
		filters = append(filters, fmt.Sprintf("(requestResult eq %s)", upper))
	}
	if v, _ := cmd.Flags().GetString("priority"); v != "" {
		if !validPriorities[v] {
			return fmt.Errorf("--priority must be one of High, Medium, Low (got %q)", v)
		}
		filters = append(filters, fmt.Sprintf("(priority eq '%s')", v))
	}
	if len(filters) > 0 {
		params.Filter = "(" + strings.Join(filters, " and ") + ")"
	}

	if v, _ := cmd.Flags().GetString("search"); v != "" {
		params.FreeText = v
	}

	if v, _ := cmd.Flags().GetString("role"); v != "" {
		role := strings.ToUpper(v)
		if role != "CREATOR" && role != "APPROVER" {
			return errors.New("--role must be CREATOR or APPROVER")
		}
		params.RequestRole = role
	}

	sortField, _ := cmd.Flags().GetString("sort")
	desc, _ := cmd.Flags().GetBool("desc")
	if sortField != "" {
		if !validSorts[sortField] {
			return fmt.Errorf("--sort must be one of createdAt, updatedAt, calculatedRequestStartTime (got %q)", sortField)
		}
		order := "asc"
		if desc {
			order = "desc"
		}
		params.Sort = sortField + " " + order
	}

	log.Info("Listing access requests with params: filter=%q freeText=%q role=%q sort=%q",
		params.Filter, params.FreeText, params.RequestRole, params.Sort)

	items, totalCount, err := svc.ListRequests(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to list requests: %w", err)
	}

	if isJSONOutput() {
		outputs := make([]accessRequestOutput, len(items))
		for i := range items {
			outputs[i] = toAccessRequestOutput(&items[i])
		}
		return writeJSON(cmd.OutOrStdout(), accessRequestListOutput{
			Requests:   outputs,
			TotalCount: totalCount,
		})
	}

	if len(items) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No access requests found.")
		return nil
	}

	formatRequestTable(cmd, items)
	fmt.Fprintf(cmd.OutOrStdout(), "\nTotal: %d\n", totalCount)
	return nil
}
