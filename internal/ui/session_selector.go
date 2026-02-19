package ui

import (
	"fmt"
	"os"
	"sort"

	"github.com/Iilun/survey/v2"
	"github.com/aaearon/grant-cli/internal/sca/models"
)

// FormatSessionOption formats a session for display in the multi-select UI.
func FormatSessionOption(session models.SessionInfo, nameMap map[string]string) string {
	durationMin := session.SessionDuration / 60
	var durationStr string
	if durationMin >= 60 {
		durationStr = fmt.Sprintf("%dh %dm", durationMin/60, durationMin%60)
	} else {
		durationStr = fmt.Sprintf("%dm", durationMin)
	}

	if session.IsGroupSession() {
		directory := session.WorkspaceID
		if nameMap != nil {
			if name, ok := nameMap[session.WorkspaceID]; ok {
				directory = name
			}
		}
		return fmt.Sprintf("Group: %s in %s - duration: %s (session: %s)", session.Target.ID, directory, durationStr, session.SessionID)
	}

	workspace := session.WorkspaceID
	if nameMap != nil {
		if name, ok := nameMap[session.WorkspaceID]; ok {
			workspace = fmt.Sprintf("%s (%s)", name, session.WorkspaceID)
		}
	}

	return fmt.Sprintf("%s on %s - duration: %s (session: %s)", session.RoleID, workspace, durationStr, session.SessionID)
}

// BuildSessionOptions builds a sorted list of display options from sessions.
func BuildSessionOptions(sessions []models.SessionInfo, nameMap map[string]string) []string {
	options := make([]string, len(sessions))
	for i, s := range sessions {
		options[i] = FormatSessionOption(s, nameMap)
	}
	sort.Strings(options)
	return options
}

// FindSessionByDisplay finds a session by its formatted display string.
func FindSessionByDisplay(sessions []models.SessionInfo, nameMap map[string]string, display string) (*models.SessionInfo, error) {
	for i := range sessions {
		if FormatSessionOption(sessions[i], nameMap) == display {
			return &sessions[i], nil
		}
	}
	return nil, fmt.Errorf("session not found: %s", display)
}

// SelectSessions presents a multi-select prompt for choosing sessions to revoke.
func SelectSessions(sessions []models.SessionInfo, nameMap map[string]string) ([]models.SessionInfo, error) {
	if len(sessions) == 0 {
		return nil, fmt.Errorf("no sessions available")
	}

	options := BuildSessionOptions(sessions, nameMap)

	var selected []string
	prompt := &survey.MultiSelect{
		Message: "Select sessions to revoke:",
		Options: options,
	}

	if err := survey.AskOne(prompt, &selected, survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)); err != nil {
		return nil, fmt.Errorf("session selection failed: %w", err)
	}

	if len(selected) == 0 {
		return nil, fmt.Errorf("no sessions selected")
	}

	var result []models.SessionInfo
	for _, display := range selected {
		s, err := FindSessionByDisplay(sessions, nameMap, display)
		if err != nil {
			return nil, err
		}
		result = append(result, *s)
	}

	return result, nil
}

// ConfirmRevocation prompts the user to confirm session revocation.
func ConfirmRevocation(count int) (bool, error) {
	var confirmed bool
	prompt := &survey.Confirm{
		Message: fmt.Sprintf("Revoke %d session(s)?", count),
		Default: false,
	}

	if err := survey.AskOne(prompt, &confirmed, survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)); err != nil {
		return false, fmt.Errorf("confirmation failed: %w", err)
	}

	return confirmed, nil
}
