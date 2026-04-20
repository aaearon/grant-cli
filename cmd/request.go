package cmd

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aaearon/grant-cli/internal/workflows"
	"github.com/aaearon/grant-cli/internal/workflows/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	"github.com/spf13/cobra"
)

// NewRequestCommand creates the "grant request" parent command.
func NewRequestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "request",
		Short: "Manage access requests",
		Long:  "Create, list, and manage access requests through the approval workflow.",
	}

	cmd.AddCommand(
		newRequestListCommand(nil),
		newRequestGetCommand(nil),
		newRequestSubmitCommand(nil),
		newRequestCancelCommand(nil),
		newRequestApproveCommand(nil),
		newRequestRejectCommand(nil),
	)

	return cmd
}

// NewRequestCommandWithDeps creates the request parent with injected dependencies for testing.
func NewRequestCommandWithDeps(reqSvc accessRequestService) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "request",
		Short: "Manage access requests",
	}

	cmd.AddCommand(
		newRequestListCommand(reqSvc),
		newRequestGetCommand(reqSvc),
		newRequestSubmitCommand(reqSvc),
		newRequestCancelCommand(reqSvc),
		newRequestApproveCommand(reqSvc),
		newRequestRejectCommand(reqSvc),
	)

	return cmd
}

// bootstrapWorkflowsService creates an authenticated AccessRequestService.
func bootstrapWorkflowsService() (*workflows.AccessRequestService, error) {
	loader := profiles.DefaultProfilesLoader()
	profile, err := (*loader).LoadProfile("grant")
	if err != nil {
		return nil, fmt.Errorf("failed to load profile: %w", err)
	}

	ispAuth := auth.NewIdsecISPAuth(true)

	_, err = ispAuth.Authenticate(profile, nil, &authmodels.IdsecSecret{Secret: ""}, false, true)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	svc, err := workflows.NewAccessRequestService(ispAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to create access request service: %w", err)
	}

	return svc, nil
}

// formatRequestTable writes a table of access requests to the command output.
func formatRequestTable(cmd *cobra.Command, requests []models.AccessRequest) {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSTATE\tRESULT\tTARGET\tROLE\tPRIORITY\tCREATED BY\tCREATED AT")
	for _, r := range requests {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.RequestID,
			r.RequestState,
			r.RequestResult,
			r.DetailString("workspaceName"),
			r.DetailString("roleName"),
			r.DetailString("priority"),
			r.CreatedBy,
			formatTimestamp(r.CreatedAt),
		)
	}
	w.Flush()
}

// formatRequestDetail writes a detailed view of a single access request.
func formatRequestDetail(cmd *cobra.Command, r *models.AccessRequest) {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Request ID:    %s\n", r.RequestID)
	fmt.Fprintf(w, "State:         %s\n", r.RequestState)
	fmt.Fprintf(w, "Result:        %s\n", r.RequestResult)
	fmt.Fprintf(w, "Category:      %s\n", r.TargetCategory)

	if v := r.DetailString("locationType"); v != "" {
		fmt.Fprintf(w, "Provider:      %s\n", v)
	}
	if v := r.DetailString("workspaceName"); v != "" {
		fmt.Fprintf(w, "Target:        %s\n", v)
	}
	if v := r.DetailString("roleName"); v != "" {
		fmt.Fprintf(w, "Role:          %s\n", v)
	}
	if v := r.DetailString("reason"); v != "" {
		fmt.Fprintf(w, "Reason:        %s\n", v)
	}
	if v := r.DetailString("priority"); v != "" {
		fmt.Fprintf(w, "Priority:      %s\n", v)
	}
	if v := r.DetailString("requestDate"); v != "" {
		fmt.Fprintf(w, "Request Date:  %s\n", v)
	}
	if v := r.DetailString("timezone"); v != "" {
		fmt.Fprintf(w, "Timezone:      %s\n", v)
	}
	if v := r.DetailString("timeFrom"); v != "" {
		fmt.Fprintf(w, "Time From:     %s\n", v)
	}
	if v := r.DetailString("timeTo"); v != "" {
		fmt.Fprintf(w, "Time To:       %s\n", v)
	}

	fmt.Fprintf(w, "Created By:    %s\n", r.CreatedBy)
	fmt.Fprintf(w, "Created At:    %s\n", formatTimestamp(r.CreatedAt))
	fmt.Fprintf(w, "Updated By:    %s\n", r.UpdatedBy)
	fmt.Fprintf(w, "Updated At:    %s\n", formatTimestamp(r.UpdatedAt))

	if r.FinalizationReason != "" {
		fmt.Fprintf(w, "Finalization:  %s\n", r.FinalizationReason)
	}
	if r.RequestLink != "" {
		fmt.Fprintf(w, "Link:          %s\n", r.RequestLink)
	}

	if len(r.AssignedApprovers) > 0 {
		names := make([]string, len(r.AssignedApprovers))
		for i, a := range r.AssignedApprovers {
			if a.EntityDisplayName != "" {
				names[i] = fmt.Sprintf("%s (%s)", a.EntityDisplayName, a.EntityEmail)
			} else {
				names[i] = a.EntityName
			}
		}
		fmt.Fprintf(w, "Approvers:     %s\n", strings.Join(names, ", "))
	}

	if len(r.RequestApprovers) > 0 {
		for _, a := range r.RequestApprovers {
			name := a.Approver.EntityDisplayName
			if name == "" {
				name = a.Approver.EntityName
			}
			fmt.Fprintf(w, "Acted:         %s - %s\n", name, a.Result)
		}
	}
}

// formatTimestamp strips fractional seconds from a timestamp while preserving
// timezone offset information. RFC3339 timestamps (with Z or ±HH:MM timezone
// offset) are parsed with RFC3339Nano and reformatted as RFC3339 (no subseconds),
// keeping the original offset. Non-RFC3339 timestamps have the fractional-seconds
// portion trimmed if present.
func formatTimestamp(ts string) string {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t.Format("2006-01-02T15:04:05Z07:00")
	}
	// Non-RFC3339 timestamps (e.g. no timezone): trim fractional seconds if present.
	if i := strings.IndexByte(ts, '.'); i >= 0 {
		return ts[:i]
	}
	return ts
}

// toAccessRequestOutput converts a model to the JSON output type.
func toAccessRequestOutput(r *models.AccessRequest) accessRequestOutput {
	return accessRequestOutput{
		RequestID:          r.RequestID,
		TargetCategory:     r.TargetCategory,
		State:              string(r.RequestState),
		Result:             string(r.RequestResult),
		Priority:           r.DetailString("priority"),
		Reason:             r.DetailString("reason"),
		Provider:           r.DetailString("locationType"),
		Target:             r.DetailString("workspaceName"),
		Role:               r.DetailString("roleName"),
		RequestDate:        r.DetailString("requestDate"),
		Timezone:           r.DetailString("timezone"),
		TimeFrom:           r.DetailString("timeFrom"),
		TimeTo:             r.DetailString("timeTo"),
		FinalizationReason: r.FinalizationReason,
		RequestLink:        r.RequestLink,
		CreatedBy:          r.CreatedBy,
		CreatedAt:          r.CreatedAt,
		UpdatedBy:          r.UpdatedBy,
		UpdatedAt:          r.UpdatedAt,
	}
}
