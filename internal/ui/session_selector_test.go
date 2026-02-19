package ui

import (
	"testing"

	"github.com/aaearon/grant-cli/internal/sca/models"
)

func TestFormatSessionOption(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		session models.SessionInfo
		nameMap map[string]string
		want    string
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatSessionOption(tt.session, tt.nameMap)
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
	options := BuildSessionOptions(sessions, nameMap)

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
		display := FormatSessionOption(sessions[0], nameMap)
		found, err := FindSessionByDisplay(sessions, nameMap, display)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found.SessionID != "s1" {
			t.Errorf("SessionID = %q, want %q", found.SessionID, "s1")
		}
	})

	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		_, err := FindSessionByDisplay(sessions, nameMap, "nonexistent")
		if err == nil {
			t.Fatal("expected error for not found")
		}
	})

	t.Run("empty list", func(t *testing.T) {
		t.Parallel()
		_, err := FindSessionByDisplay(nil, nameMap, "anything")
		if err == nil {
			t.Fatal("expected error for empty list")
		}
	})
}
