package ui

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aaearon/grant-cli/internal/sca/models"
)

func TestFormatSessionOption(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		session      models.SessionInfo
		nameMap      map[string]string
		groupNameMap map[string]string
		remainingMap map[string]time.Duration
		want         string
	}{
		{
			name: "with workspace name",
			session: models.SessionInfo{
				SessionID:       "session-1",
				CSP:             models.CSPAzure,
				WorkspaceID:     "/subscriptions/sub-1",
				RoleID:          "Contributor",
				SessionDuration: 3600,
			},
			nameMap: map[string]string{"/subscriptions/sub-1": "My Subscription"},
			want:    "Contributor on My Subscription (/subscriptions/sub-1) - duration: 1h 0m (session: session-1)",
		},
		{
			name: "without workspace name",
			session: models.SessionInfo{
				SessionID:       "session-2",
				CSP:             models.CSPAzure,
				WorkspaceID:     "/subscriptions/sub-2",
				RoleID:          "Reader",
				SessionDuration: 2700,
			},
			nameMap: map[string]string{},
			want:    "Reader on /subscriptions/sub-2 - duration: 45m (session: session-2)",
		},
		{
			name: "nil name map",
			session: models.SessionInfo{
				SessionID:       "session-3",
				CSP:             models.CSPAWS,
				WorkspaceID:     "arn:aws:iam::123:role/Admin",
				RoleID:          "Admin",
				SessionDuration: 1800,
			},
			nameMap: nil,
			want:    "Admin on arn:aws:iam::123:role/Admin - duration: 30m (session: session-3)",
		},
		{
			name: "duration less than a minute rounds to 0m",
			session: models.SessionInfo{
				SessionID:       "session-4",
				CSP:             models.CSPAzure,
				WorkspaceID:     "/subscriptions/sub-1",
				RoleID:          "Owner",
				SessionDuration: 30,
			},
			nameMap: map[string]string{},
			want:    "Owner on /subscriptions/sub-1 - duration: 0m (session: session-4)",
		},
		{
			name: "group session with directory name",
			session: models.SessionInfo{
				SessionID:       "group-session-1",
				CSP:             models.CSPAzure,
				WorkspaceID:     "29cb7961-e16d-42c7-8ade-1794bbb76782",
				SessionDuration: 3600,
				Target:          &models.SessionTarget{ID: "d554b344-group-uuid", Type: models.TargetTypeGroups},
			},
			nameMap: map[string]string{"29cb7961-e16d-42c7-8ade-1794bbb76782": "CyberIAM Tech Labs"},
			want:    "Group: d554b344-group-uuid in CyberIAM Tech Labs - duration: 1h 0m (session: group-session-1)",
		},
		{
			name: "group session without directory name",
			session: models.SessionInfo{
				SessionID:       "group-session-2",
				CSP:             models.CSPAzure,
				WorkspaceID:     "29cb7961-dir-uuid",
				SessionDuration: 1800,
				Target:          &models.SessionTarget{ID: "abcd-group-uuid", Type: models.TargetTypeGroups},
			},
			nameMap: map[string]string{},
			want:    "Group: abcd-group-uuid in 29cb7961-dir-uuid - duration: 30m (session: group-session-2)",
		},
		{
			name: "group session with nil name map",
			session: models.SessionInfo{
				SessionID:       "group-session-3",
				CSP:             models.CSPAzure,
				WorkspaceID:     "dir-uuid-123",
				SessionDuration: 7200,
				Target:          &models.SessionTarget{ID: "group-uuid-456", Type: models.TargetTypeGroups},
			},
			nameMap: nil,
			want:    "Group: group-uuid-456 in dir-uuid-123 - duration: 2h 0m (session: group-session-3)",
		},
		{
			name: "group session with group name resolved",
			session: models.SessionInfo{
				SessionID:       "group-session-4",
				CSP:             models.CSPAzure,
				WorkspaceID:     "dir-uuid-100",
				SessionDuration: 3600,
				Target:          &models.SessionTarget{ID: "grp-uuid-200", Type: models.TargetTypeGroups},
			},
			nameMap:      map[string]string{"dir-uuid-100": "Contoso"},
			groupNameMap: map[string]string{"grp-uuid-200": "CloudAdmins"},
			want:         "Group: CloudAdmins in Contoso - duration: 1h 0m (session: group-session-4)",
		},
		{
			name: "group session without group name falls back to UUID",
			session: models.SessionInfo{
				SessionID:       "group-session-5",
				CSP:             models.CSPAzure,
				WorkspaceID:     "dir-uuid-100",
				SessionDuration: 3600,
				Target:          &models.SessionTarget{ID: "grp-uuid-300", Type: models.TargetTypeGroups},
			},
			nameMap:      map[string]string{"dir-uuid-100": "Contoso"},
			groupNameMap: map[string]string{},
			want:         "Group: grp-uuid-300 in Contoso - duration: 1h 0m (session: group-session-5)",
		},
		{
			name: "session with remaining time",
			session: models.SessionInfo{
				SessionID:       "session-rem-1",
				CSP:             models.CSPAzure,
				WorkspaceID:     "/subscriptions/sub-1",
				RoleID:          "Contributor",
				SessionDuration: 3600,
			},
			nameMap:      map[string]string{},
			remainingMap: map[string]time.Duration{"session-rem-1": 45 * time.Minute},
			want:         "Contributor on /subscriptions/sub-1 - remaining: 45m (session: session-rem-1)",
		},
		{
			name: "session with remaining time <= 0 shows expired",
			session: models.SessionInfo{
				SessionID:       "session-rem-2",
				CSP:             models.CSPAzure,
				WorkspaceID:     "/subscriptions/sub-1",
				RoleID:          "Reader",
				SessionDuration: 3600,
			},
			nameMap:      map[string]string{},
			remainingMap: map[string]time.Duration{"session-rem-2": -5 * time.Minute},
			want:         "Reader on /subscriptions/sub-1 - expired (session: session-rem-2)",
		},
		{
			name: "session without remaining time shows duration (backwards compat)",
			session: models.SessionInfo{
				SessionID:       "session-no-rem",
				CSP:             models.CSPAzure,
				WorkspaceID:     "/subscriptions/sub-1",
				RoleID:          "Owner",
				SessionDuration: 3600,
			},
			nameMap:      map[string]string{},
			remainingMap: map[string]time.Duration{},
			want:         "Owner on /subscriptions/sub-1 - duration: 1h 0m (session: session-no-rem)",
		},
		{
			name: "nil maps identical to current behavior (backwards compat)",
			session: models.SessionInfo{
				SessionID:       "session-nil-maps",
				CSP:             models.CSPAzure,
				WorkspaceID:     "/subscriptions/sub-1",
				RoleID:          "Reader",
				SessionDuration: 1800,
			},
			nameMap:      nil,
			groupNameMap: nil,
			remainingMap: nil,
			want:         "Reader on /subscriptions/sub-1 - duration: 30m (session: session-nil-maps)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatSessionOption(tt.session, tt.nameMap, tt.groupNameMap, tt.remainingMap)
			if got != tt.want {
				t.Errorf("FormatSessionOption() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildSessionOptions(t *testing.T) {
	t.Parallel()
	sessions := []models.SessionInfo{
		{SessionID: "s2", RoleID: "Reader", WorkspaceID: "ws-b", SessionDuration: 1800},
		{SessionID: "s1", RoleID: "Admin", WorkspaceID: "ws-a", SessionDuration: 3600},
	}
	nameMap := map[string]string{}
	options := BuildSessionOptions(sessions, nameMap, nil, nil)

	if len(options) != 2 {
		t.Fatalf("expected 2 options, got %d", len(options))
	}
	// Should be sorted alphabetically
	if options[0] >= options[1] {
		t.Errorf("expected sorted options, got %q before %q", options[0], options[1])
	}
}

func TestFindSessionByDisplay(t *testing.T) {
	t.Parallel()
	sessions := []models.SessionInfo{
		{SessionID: "s1", RoleID: "Admin", WorkspaceID: "ws-a", SessionDuration: 3600},
		{SessionID: "s2", RoleID: "Reader", WorkspaceID: "ws-b", SessionDuration: 1800},
	}
	nameMap := map[string]string{}

	t.Run("found", func(t *testing.T) {
		t.Parallel()
		display := FormatSessionOption(sessions[0], nameMap, nil, nil)
		found, err := FindSessionByDisplay(sessions, nameMap, nil, nil, display)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found.SessionID != "s1" {
			t.Errorf("SessionID = %q, want %q", found.SessionID, "s1")
		}
	})

	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		_, err := FindSessionByDisplay(sessions, nameMap, nil, nil, "nonexistent")
		if err == nil {
			t.Fatal("expected error for not found")
		}
	})

	t.Run("empty list", func(t *testing.T) {
		t.Parallel()
		_, err := FindSessionByDisplay(nil, nameMap, nil, nil, "anything")
		if err == nil {
			t.Fatal("expected error for empty list")
		}
	})
}

func TestSelectSessions_NonTTY(t *testing.T) {
	t.Parallel()
	original := IsTerminalFunc
	defer func() { IsTerminalFunc = original }()
	IsTerminalFunc = func(fd uintptr) bool { return false }

	sessions := []models.SessionInfo{
		{SessionID: "s1", RoleID: "Admin", WorkspaceID: "ws-a", SessionDuration: 3600},
	}

	_, err := SelectSessions(sessions, nil)
	if err == nil {
		t.Fatal("expected error for non-TTY")
	}
	if !errors.Is(err, ErrNotInteractive) {
		t.Errorf("expected ErrNotInteractive, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--all") {
		t.Errorf("error should mention --all, got: %v", err)
	}
}

func TestConfirmRevocation_NonTTY(t *testing.T) {
	t.Parallel()
	original := IsTerminalFunc
	defer func() { IsTerminalFunc = original }()
	IsTerminalFunc = func(fd uintptr) bool { return false }

	_, err := ConfirmRevocation(3)
	if err == nil {
		t.Fatal("expected error for non-TTY")
	}
	if !errors.Is(err, ErrNotInteractive) {
		t.Errorf("expected ErrNotInteractive, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("error should mention --yes, got: %v", err)
	}
}
