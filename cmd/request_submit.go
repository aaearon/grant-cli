package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	survey "github.com/Iilun/survey/v2"
	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/aaearon/grant-cli/internal/ui"
	wfmodels "github.com/aaearon/grant-cli/internal/workflows/models"
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
	cmd.Flags().StringP("role", "r", "", "Role name")
	cmd.Flags().String("reason", "", "Reason for the request (required)")
	cmd.Flags().String("priority", "Medium", "Priority: High, Medium, Low")
	cmd.Flags().String("date", "", "Request date (YYYY-MM-DD)")
	cmd.Flags().String("timezone", "", "Timezone (TZ identifier, e.g. America/New_York)")
	cmd.Flags().String("from", "", "Start time (HH:MM)")
	cmd.Flags().String("to", "", "End time (HH:MM)")
	cmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")

	return cmd
}

// submitPromptFn is injectable for testing interactive prompts.
var submitPromptFn = defaultSubmitPrompt

// confirmSubmitFn is injectable for testing the confirmation prompt.
var confirmSubmitFn = confirmSubmit

// resolveSubmitTargetFn is injectable for testing target resolution.
var resolveSubmitTargetFn = resolveSubmitTarget

type submitFields struct {
	reason   string
	priority string
	date     string
	timezone string
	timeFrom string
	timeTo   string
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

	// 5. Start time
	if existing.timeFrom == "" {
		if err := survey.AskOne(&survey.Input{Message: "Start time (HH:MM):"}, &f.timeFrom,
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

	// 6. End time
	if existing.timeTo == "" {
		if err := survey.AskOne(&survey.Input{Message: "End time (HH:MM):"}, &f.timeTo,
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

	fields, err := resolveSubmitFields(cmd)
	if err != nil {
		return err
	}

	if err := validateSubmitFields(fields); err != nil {
		return err
	}

	targetName, _ := cmd.Flags().GetString("target")
	roleName, _ := cmd.Flags().GetString("role")

	ctx, cancel := context.WithTimeout(cmd.Context(), apiTimeout)
	defer cancel()

	target, err := resolveSubmitTargetFn(ctx, provider, targetName, roleName)
	if err != nil {
		return err
	}

	// Summary before submission
	if !isJSONOutput() {
		fmt.Fprintf(cmd.ErrOrStderr(), "\nTarget:   %s / %s\n", target.WorkspaceName, target.RoleInfo.Name)
		fmt.Fprintf(cmd.ErrOrStderr(), "Date:     %s\n", fields.date)
		fmt.Fprintf(cmd.ErrOrStderr(), "Time:     %s – %s (%s)\n", fields.timeFrom, fields.timeTo, fields.timezone)
		fmt.Fprintf(cmd.ErrOrStderr(), "Priority: %s\n", fields.priority)
		fmt.Fprintf(cmd.ErrOrStderr(), "Reason:   %s\n\n", fields.reason)
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

	details := buildRequestDetails(target, fields)

	log.Info("Submitting access request for %s / %s", target.WorkspaceName, target.RoleInfo.Name)

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

func resolveSubmitTarget(ctx context.Context, provider, targetName, roleName string) (*models.EligibleTarget, error) {
	_, scaSvc, _, err := bootstrapSCAService()
	if err != nil {
		return nil, fmt.Errorf("failed to bootstrap SCA service: %w", err)
	}

	cfg, _, _ := config.LoadDefaultWithPath()
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	cachedLister := buildCachedLister(cfg, false, scaSvc, nil)

	fetchCtx, fetchCancel := context.WithTimeout(ctx, apiTimeout)
	defer fetchCancel()

	targets, err := fetchEligibility(fetchCtx, cachedLister, provider)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch eligibility: %w", err)
	}

	if targetName != "" && roleName != "" {
		target := findMatchingTarget(targets, targetName, roleName)
		if target == nil {
			return nil, fmt.Errorf("no eligible target found matching target=%q role=%q", targetName, roleName)
		}
		resolveTargetCSP(target, targets, provider)
		return target, nil
	}

	// Partial --target: filter to matching workspaces
	if targetName != "" && roleName == "" {
		var filtered []models.EligibleTarget
		for i := range targets {
			if strings.EqualFold(targets[i].WorkspaceName, targetName) {
				filtered = append(filtered, targets[i])
			}
		}
		if len(filtered) == 0 {
			return nil, fmt.Errorf("no eligible target found matching target=%q", targetName)
		}
		if len(filtered) == 1 {
			resolveTargetCSP(&filtered[0], targets, provider)
			return &filtered[0], nil
		}
		targets = filtered
	}

	// Partial --role: filter to matching roles
	if roleName != "" && targetName == "" {
		var filtered []models.EligibleTarget
		for i := range targets {
			if strings.EqualFold(targets[i].RoleInfo.Name, roleName) {
				filtered = append(filtered, targets[i])
			}
		}
		if len(filtered) == 0 {
			return nil, fmt.Errorf("no eligible target found matching role=%q", roleName)
		}
		if len(filtered) == 1 {
			resolveTargetCSP(&filtered[0], targets, provider)
			return &filtered[0], nil
		}
		targets = filtered
	}

	if !ui.IsInteractive() {
		return nil, errors.New("non-interactive mode requires --target and --role")
	}
	items := buildCloudSelectionItems(targets)
	sel := &uiUnifiedSelector{}
	selected, err := sel.SelectItem(items)
	if err != nil {
		return nil, err
	}
	resolveTargetCSP(selected.cloud, targets, provider)
	return selected.cloud, nil
}

// API submit payload uses camelCase keys (per spec example), not the snake_case
// form question keys from GET /request-forms.
func buildRequestDetails(target *models.EligibleTarget, f *submitFields) map[string]interface{} {
	locationType := string(target.CSP)
	if target.CSP == models.CSPAzure {
		locationType = "Azure"
	} else if target.CSP == models.CSPAWS {
		locationType = "AWS"
	}

	return map[string]interface{}{
		"locationType":  locationType,
		"roleId":        target.RoleInfo.ID,
		"roleName":      target.RoleInfo.Name,
		"workspaceId":   target.WorkspaceID,
		"workspaceName": target.WorkspaceName,
		"workspaceType": string(target.WorkspaceType),
		"orgId":         target.OrganizationID,
		"reason":        f.reason,
		"priority":      f.priority,
		"requestDate":   f.date,
		"timezone":      f.timezone,
		"timeFrom":      f.timeFrom,
		"timeTo":        f.timeTo,
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

// buildCloudSelectionItems wraps cloud targets in selectionItems for the unified selector.
func buildCloudSelectionItems(targets []models.EligibleTarget) []selectionItem {
	items := make([]selectionItem, len(targets))
	for i := range targets {
		items[i] = selectionItem{
			kind:  selectionCloud,
			cloud: &targets[i],
		}
	}
	return items
}
