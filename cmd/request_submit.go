package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	survey "github.com/Iilun/survey/v2"
	"github.com/aaearon/grant-cli/internal/cache"
	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/aaearon/grant-cli/internal/ui"
	wfmodels "github.com/aaearon/grant-cli/internal/workflows/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/spf13/cobra"
)

func newRequestSubmitCommand(svc accessRequestService) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "submit",
		Short: "Submit an access request",
		Long:  "Submit a new access request for cloud resource access through the approval workflow.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if svc == nil {
				bootstrapped, err := bootstrapWorkflowsService()
				if err != nil {
					return err
				}
				svc = bootstrapped
			}
			return runRequestSubmit(cmd, svc)
		},
	}

	cmd.Flags().StringP("provider", "p", "", "Cloud provider: azure, aws")
	cmd.Flags().StringP("target", "t", "", "Target workspace name")
	cmd.Flags().String("role-id", "", "Role ID to request access for (required)")
	cmd.Flags().StringP("role", "r", "", "Role name (display only)")
	cmd.Flags().String("reason", "", "Reason for the request (required)")
	cmd.Flags().String("priority", "Medium", "Priority: High, Medium, Low")
	cmd.Flags().String("date", "", "Request date (YYYY-MM-DD)")
	cmd.Flags().String("timezone", "", "Timezone (TZ identifier, e.g. America/New_York)")
	cmd.Flags().String("from", "", "Start time (HH:MM)")
	cmd.Flags().String("to", "", "End time (HH:MM)")
	cmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")
	cmd.Flags().Bool("refresh", false, "Bypass on-demand role and eligibility caches")

	return cmd
}

// submitPromptFn is injectable for testing interactive prompts.
var submitPromptFn = defaultSubmitPrompt

// confirmSubmitFn is injectable for testing the confirmation prompt.
var confirmSubmitFn = confirmSubmit

// resolveSubmitTargetFn is injectable for testing target resolution.
var resolveSubmitTargetFn = resolveSubmitTarget

// submitWorkspaceSelectorFn is injectable for testing workspace selection.
var submitWorkspaceSelectorFn = selectSubmitWorkspace

// resolveRoleFn is injectable for testing role resolution.
var resolveRoleFn = resolveSubmitRole

type submitFields struct {
	reason   string
	priority string
	date     string
	timezone string
	timeFrom string
	timeTo   string
}

// submitWorkspace holds deduplicated workspace info derived from eligibility.
type submitWorkspace struct {
	WorkspaceID   string
	WorkspaceName string
	WorkspaceType models.WorkspaceType
	CSP           models.CSP
	OrganizationID string
}

func resolveLocalTimezone() string {
	tz := time.Now().Location().String()
	if tz == "Local" {
		if env := os.Getenv("TZ"); env != "" {
			return env
		}
		return "UTC"
	}
	return tz
}

func defaultSubmitPrompt(existing *submitFields) (*submitFields, error) {
	if !ui.IsInteractive() {
		return nil, fmt.Errorf("%w; use --reason, --date, --timezone, --from, --to flags", ui.ErrNotInteractive)
	}

	stdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
	f := &submitFields{}

	// 1. Reason
	if existing.reason == "" {
		if err := survey.AskOne(&survey.Input{Message: "Reason:"}, &f.reason, survey.WithValidator(survey.Required), stdio); err != nil {
			return nil, err
		}
	}

	// 2. Priority
	if existing.priority == "" || existing.priority == "Medium" {
		var priority string
		if err := survey.AskOne(&survey.Select{
			Message: "Priority:",
			Options: []string{"High", "Medium", "Low"},
			Default: "Medium",
		}, &priority, stdio); err != nil {
			return nil, err
		}
		f.priority = priority
	}

	// 3. Timezone (before date so we can compute correct default date)
	if existing.timezone == "" {
		localTZ := resolveLocalTimezone()
		if err := survey.AskOne(&survey.Input{Message: "Timezone:", Default: localTZ}, &f.timezone,
			survey.WithValidator(func(val interface{}) error {
				s, _ := val.(string)
				if _, err := time.LoadLocation(s); err != nil {
					return errors.New("must be a valid timezone (e.g. America/New_York, UTC)")
				}
				return nil
			}), stdio); err != nil {
			return nil, err
		}
	}

	// 4. Date (default: today in selected timezone)
	if existing.date == "" {
		tz := f.timezone
		if tz == "" {
			tz = existing.timezone
		}
		loc, _ := time.LoadLocation(tz)
		today := time.Now().In(loc).Format("2006-01-02")
		if err := survey.AskOne(&survey.Input{Message: "Date (YYYY-MM-DD):", Default: today}, &f.date,
			survey.WithValidator(func(val interface{}) error {
				s, _ := val.(string)
				if _, err := time.Parse("2006-01-02", s); err != nil {
					return errors.New("must be YYYY-MM-DD format")
				}
				return nil
			}), stdio); err != nil {
			return nil, err
		}
	}

	// 5. Start time (default: current time in selected timezone)
	if existing.timeFrom == "" {
		tz := f.timezone
		if tz == "" {
			tz = existing.timezone
		}
		loc, _ := time.LoadLocation(tz)
		defaultStart := time.Now().In(loc).Format("15:04")
		if err := survey.AskOne(&survey.Input{Message: "Start time (HH:MM):", Default: defaultStart}, &f.timeFrom,
			survey.WithValidator(func(val interface{}) error {
				s, _ := val.(string)
				if _, err := time.Parse("15:04", s); err != nil {
					return errors.New("must be HH:MM format")
				}
				return nil
			}), stdio); err != nil {
			return nil, err
		}
	}

	// 6. End time (default: start + 1 hour)
	if existing.timeTo == "" {
		startTime := f.timeFrom
		if startTime == "" {
			startTime = existing.timeFrom
		}
		defaultEnd := ""
		if parsed, parseErr := time.Parse("15:04", startTime); parseErr == nil {
			defaultEnd = parsed.Add(time.Hour).Format("15:04")
		}
		if err := survey.AskOne(&survey.Input{Message: "End time (HH:MM):", Default: defaultEnd}, &f.timeTo,
			survey.WithValidator(func(val interface{}) error {
				s, _ := val.(string)
				if _, err := time.Parse("15:04", s); err != nil {
					return errors.New("must be HH:MM format")
				}
				return nil
			}), stdio); err != nil {
			return nil, err
		}
	}

	return f, nil
}

func confirmSubmit() (bool, error) {
	if !ui.IsInteractive() {
		return false, fmt.Errorf("%w; use --yes to skip confirmation", ui.ErrNotInteractive)
	}
	var confirmed bool
	err := survey.AskOne(&survey.Confirm{Message: "Submit this request?"}, &confirmed,
		survey.WithStdio(os.Stdin, os.Stderr, os.Stderr))
	return confirmed, err
}

func runRequestSubmit(cmd *cobra.Command, svc accessRequestService) error {
	provider, _ := cmd.Flags().GetString("provider")
	if provider != "" {
		if _, err := parseProvider(provider); err != nil {
			return err
		}
	}

	targetName, _ := cmd.Flags().GetString("target")
	roleID, _ := cmd.Flags().GetString("role-id")
	roleName, _ := cmd.Flags().GetString("role")
	refresh, _ := cmd.Flags().GetBool("refresh")

	ctx, cancel := context.WithTimeout(cmd.Context(), apiTimeout)
	defer cancel()

	// 1. Workspace
	workspace, err := resolveSubmitTargetFn(ctx, provider, targetName, refresh)
	if err != nil {
		return err
	}

	// 2. Role
	if roleID == "" {
		if !ui.IsInteractive() {
			return errors.New("non-interactive mode requires --role-id")
		}
		resolvedID, resolvedName, err := resolveRoleFn(ctx, workspace, refresh)
		if err != nil {
			return fmt.Errorf("%w; retry with --role-id to bypass interactive role selection", err)
		}
		roleID = resolvedID
		if roleName == "" {
			roleName = resolvedName
		}
	}

	if roleName == "" {
		roleName = roleID
	}

	// 3–8. Reason, priority, timezone, date, start time, end time
	fields, err := resolveSubmitFields(cmd)
	if err != nil {
		return err
	}

	if err := validateSubmitFields(fields); err != nil {
		return err
	}

	// Summary before submission
	if !isJSONOutput() {
		fmt.Fprintf(cmd.ErrOrStderr(), "\nWorkspace: %s\n", workspace.WorkspaceName)
		fmt.Fprintf(cmd.ErrOrStderr(), "Role:      %s (ID: %s)\n", roleName, roleID)
		fmt.Fprintf(cmd.ErrOrStderr(), "Date:      %s\n", fields.date)
		fmt.Fprintf(cmd.ErrOrStderr(), "Time:      %s – %s (%s)\n", fields.timeFrom, fields.timeTo, fields.timezone)
		fmt.Fprintf(cmd.ErrOrStderr(), "Priority:  %s\n", fields.priority)
		fmt.Fprintf(cmd.ErrOrStderr(), "Reason:    %s\n\n", fields.reason)
	}

	// Confirmation
	yesFlag, _ := cmd.Flags().GetBool("yes")
	if !yesFlag && !isJSONOutput() {
		confirmed, confirmErr := confirmSubmitFn()
		if confirmErr != nil {
			return confirmErr
		}
		if !confirmed {
			fmt.Fprintln(cmd.OutOrStdout(), "Submission canceled.")
			return nil
		}
	}

	details := buildRequestDetails(workspace, roleID, roleName, fields)

	log.Info("Submitting access request for %s / %s", workspace.WorkspaceName, roleName)

	result, err := svc.SubmitRequest(ctx, &wfmodels.SubmitAccessRequest{
		TargetCategory: "CLOUD_CONSOLE",
		RequestDetails: details,
	})
	if err != nil {
		return fmt.Errorf("failed to submit request: %w", err)
	}

	if isJSONOutput() {
		return writeJSON(cmd.OutOrStdout(), toAccessRequestOutput(result))
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Access request submitted successfully.\n")
	fmt.Fprintf(cmd.OutOrStdout(), "Request ID: %s\n", result.RequestID)
	fmt.Fprintf(cmd.OutOrStdout(), "State:      %s\n", result.RequestState)
	if result.RequestLink != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "Link:       %s\n", result.RequestLink)
	}
	return nil
}

func resolveSubmitFields(cmd *cobra.Command) (*submitFields, error) {
	f := &submitFields{}
	f.reason, _ = cmd.Flags().GetString("reason")
	f.priority, _ = cmd.Flags().GetString("priority")
	f.date, _ = cmd.Flags().GetString("date")
	f.timezone, _ = cmd.Flags().GetString("timezone")
	f.timeFrom, _ = cmd.Flags().GetString("from")
	f.timeTo, _ = cmd.Flags().GetString("to")

	if f.reason != "" && f.date != "" && f.timezone != "" && f.timeFrom != "" && f.timeTo != "" {
		return f, nil
	}

	if !ui.IsInteractive() {
		return nil, errors.New("non-interactive mode requires --reason, --date, --timezone, --from, --to")
	}

	prompted, err := submitPromptFn(f)
	if err != nil {
		return nil, err
	}
	if f.reason == "" {
		f.reason = prompted.reason
	}
	if !cmd.Flags().Changed("priority") && prompted.priority != "" {
		f.priority = prompted.priority
	}
	if f.date == "" {
		f.date = prompted.date
	}
	if f.timezone == "" {
		f.timezone = prompted.timezone
	}
	if f.timeFrom == "" {
		f.timeFrom = prompted.timeFrom
	}
	if f.timeTo == "" {
		f.timeTo = prompted.timeTo
	}
	return f, nil
}

func resolveSubmitTarget(ctx context.Context, provider, targetName string, refresh bool) (*submitWorkspace, error) {
	_, scaSvc, _, err := bootstrapSCAService()
	if err != nil {
		return nil, fmt.Errorf("failed to bootstrap SCA service: %w", err)
	}

	cfg, _, _ := config.LoadDefaultWithPath()
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	cachedLister := buildCachedLister(cfg, refresh, scaSvc, nil)

	fetchCtx, fetchCancel := context.WithTimeout(ctx, apiTimeout)
	defer fetchCancel()

	targets, err := fetchEligibility(fetchCtx, cachedLister, provider)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch eligibility: %w", err)
	}

	workspaces := deduplicateWorkspaces(targets)
	if len(workspaces) == 0 {
		return nil, errors.New("no eligible workspaces found")
	}

	// Non-interactive: match by --target flag
	if targetName != "" {
		for i := range workspaces {
			if strings.EqualFold(workspaces[i].WorkspaceName, targetName) {
				return &workspaces[i], nil
			}
		}
		return nil, fmt.Errorf("no eligible workspace found matching target=%q", targetName)
	}

	// Single workspace: auto-select
	if len(workspaces) == 1 {
		return &workspaces[0], nil
	}

	// Interactive selection
	return submitWorkspaceSelectorFn(workspaces)
}

func selectSubmitWorkspace(workspaces []submitWorkspace) (*submitWorkspace, error) {
	if !ui.IsInteractive() {
		return nil, errors.New("non-interactive mode requires --target")
	}

	options := make([]string, len(workspaces))
	for i, ws := range workspaces {
		options[i] = formatWorkspaceOption(ws)
	}

	var selected int
	err := survey.AskOne(&survey.Select{
		Message: "Select a workspace:",
		Options: options,
	}, &selected, survey.WithStdio(os.Stdin, os.Stderr, os.Stderr))
	if err != nil {
		return nil, err
	}
	return &workspaces[selected], nil
}

func formatWorkspaceOption(ws submitWorkspace) string {
	label := workspaceTypeLabel(ws.WorkspaceType)
	return fmt.Sprintf("%s: %s (%s)", label, ws.WorkspaceName, strings.ToLower(string(ws.CSP)))
}

func workspaceTypeLabel(wt models.WorkspaceType) string {
	switch strings.ToUpper(string(wt)) {
	case "SUBSCRIPTION":
		return "Subscription"
	case "MANAGEMENT_GROUP":
		return "Management Group"
	case "DIRECTORY":
		return "Directory"
	case "ACCOUNT":
		return "Account"
	case "RESOURCE_GROUP":
		return "Resource Group"
	case "RESOURCE":
		return "Resource"
	default:
		return string(wt)
	}
}

func deduplicateWorkspaces(targets []models.EligibleTarget) []submitWorkspace {
	seen := make(map[string]bool)
	var result []submitWorkspace
	for _, t := range targets {
		if seen[t.WorkspaceID] {
			continue
		}
		seen[t.WorkspaceID] = true
		result = append(result, submitWorkspace{
			WorkspaceID:    t.WorkspaceID,
			WorkspaceName:  t.WorkspaceName,
			WorkspaceType:  t.WorkspaceType,
			CSP:            t.CSP,
			OrganizationID: t.OrganizationID,
		})
	}
	return result
}

func buildRequestDetails(ws *submitWorkspace, roleID, roleName string, f *submitFields) map[string]interface{} {
	locationType := string(ws.CSP)
	if ws.CSP == models.CSPAzure {
		locationType = "Azure"
	} else if ws.CSP == models.CSPAWS {
		locationType = "AWS"
	}

	return map[string]interface{}{
		"locationType":  locationType,
		"roleId":        roleID,
		"roleName":      roleName,
		"workspaceId":   ws.WorkspaceID,
		"workspaceName": ws.WorkspaceName,
		"workspaceType": string(ws.WorkspaceType),
		"orgId":         ws.OrganizationID,
		"reason":        f.reason,
		"priority":      f.priority,
		"requestDate":   f.date,
		"timezone":      f.timezone,
		"timeFrom":      f.timeFrom,
		"timeTo":        f.timeTo,
	}
}

// resolveSubmitRole fetches on-demand roles for the selected workspace and
// prompts the user to choose one. Returns the role's resource_id and resource_name.
func resolveSubmitRole(ctx context.Context, ws *submitWorkspace, refresh bool) (roleID, roleName string, _ error) {
	req, err := buildOnDemandRequest(ws)
	if err != nil {
		return "", "", err
	}

	_, scaSvc, _, err := bootstrapSCAService()
	if err != nil {
		return "", "", fmt.Errorf("failed to bootstrap SCA service: %w", err)
	}

	cfg, _, _ := config.LoadDefaultWithPath()
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	var lister cache.OnDemandRolesLister = scaSvc
	cacheDir, cacheErr := cache.CacheDir()
	if cacheErr == nil {
		ttl := config.ParseCacheTTL(cfg)
		store := cache.NewStore(cacheDir, ttl)
		lister = cache.NewCachedRolesLister(scaSvc, store, refresh, common.GetLogger("grant", -1))
	}

	fetchCtx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()

	roles, err := lister.ListOnDemandResources(fetchCtx, req)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch on-demand roles: %w", err)
	}

	selected, err := ui.SelectRole(roles)
	if err != nil {
		return "", "", err
	}
	return selected.ResourceID, selected.ResourceName, nil
}

// buildOnDemandRequest maps a workspace into the on-demand discovery request.
// ensureLeadingSlash returns s with exactly one leading slash.
func ensureLeadingSlash(s string) string {
	return "/" + strings.TrimLeft(s, "/")
}

// buildOnDemandRequest maps a workspace into the on-demand discovery request.
func buildOnDemandRequest(ws *submitWorkspace) (models.OnDemandRequest, error) {
	wt := strings.ToUpper(string(ws.WorkspaceType))
	switch wt {
	case "DIRECTORY":
		return models.OnDemandRequest{
			WorkspaceID:  ws.WorkspaceID,
			PlatformName: "azure_ad",
			OrgID:        ws.OrganizationID,
		}, nil
	case "ACCOUNT":
		return models.OnDemandRequest{
			WorkspaceID:  ws.WorkspaceID,
			PlatformName: "aws",
			OrgID:        ws.OrganizationID,
		}, nil
	case "MANAGEMENT_GROUP":
		return models.OnDemandRequest{
			WorkspaceID:  ws.WorkspaceID,
			PlatformName: "azure_resource",
			OrgID:        ws.OrganizationID,
			ResourceType: "management_group",
			Ancestors: []string{
				ensureLeadingSlash(ws.OrganizationID),
				ensureLeadingSlash(ws.WorkspaceID),
			},
		}, nil
	case "SUBSCRIPTION", "RESOURCE_GROUP", "RESOURCE":
		resourceType := map[string]string{
			"SUBSCRIPTION":   "subscription",
			"RESOURCE_GROUP": "resource_group",
			"RESOURCE":       "resource",
		}[wt]
		return models.OnDemandRequest{
			WorkspaceID:  ws.WorkspaceID,
			PlatformName: "azure_resource",
			OrgID:        ws.OrganizationID,
			ResourceType: resourceType,
			Ancestors: []string{
				ensureLeadingSlash(ws.OrganizationID),
				ensureLeadingSlash(ws.WorkspaceID),
			},
		}, nil
	default:
		return models.OnDemandRequest{}, fmt.Errorf(
			"interactive role selection not supported for workspace type %q; use --role-id",
			ws.WorkspaceType)
	}
}

func validateSubmitFields(f *submitFields) error {
	if f.reason == "" {
		return errors.New("--reason is required")
	}

	validPriorities := map[string]bool{"High": true, "Medium": true, "Low": true}
	if !validPriorities[f.priority] {
		return fmt.Errorf("--priority must be High, Medium, or Low (got %q)", f.priority)
	}

	if f.date == "" {
		return errors.New("--date is required")
	}
	if _, err := time.Parse("2006-01-02", f.date); err != nil {
		return fmt.Errorf("--date must be in YYYY-MM-DD format (got %q)", f.date)
	}

	if f.timezone == "" {
		return errors.New("--timezone is required")
	}
	if _, err := time.LoadLocation(f.timezone); err != nil {
		return fmt.Errorf("--timezone must be a valid TZ identifier (e.g. America/New_York, UTC), got %q", f.timezone)
	}

	if f.timeFrom == "" {
		return errors.New("--from is required")
	}
	if _, err := time.Parse("15:04", f.timeFrom); err != nil {
		return fmt.Errorf("--from must be in HH:MM format (got %q)", f.timeFrom)
	}

	if f.timeTo == "" {
		return errors.New("--to is required")
	}
	if _, err := time.Parse("15:04", f.timeTo); err != nil {
		return fmt.Errorf("--to must be in HH:MM format (got %q)", f.timeTo)
	}

	return nil
}
