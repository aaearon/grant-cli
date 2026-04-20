package ui

import (
	"errors"
	"strings"
	"testing"

	wfmodels "github.com/aaearon/grant-cli/internal/workflows/models"
)

func TestFormatRequestOption(t *testing.T) {
	r := wfmodels.AccessRequest{
		RequestID:    "abcdef12-3456-7890-aaaa-bbbbccccdddd",
		RequestState: wfmodels.RequestStatePending,
		CreatedBy:    "user@test",
		CreatedAt:    "2026-04-20T10:00:00Z",
		RequestDetails: map[string]any{
			"workspaceName": "prod-account",
			"roleName":      "Admin",
		},
	}
	got := FormatRequestOption(r)
	for _, want := range []string{"PENDING", "prod-account", "Admin", "user@test", "2026-04-20T10:00:00Z", "[abcdef12]"} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatRequestOption missing %q: got %q", want, got)
		}
	}
}

func TestFormatRequestOption_MissingDetails(t *testing.T) {
	r := wfmodels.AccessRequest{
		RequestID:    "short",
		RequestState: wfmodels.RequestStateRunning,
		CreatedBy:    "u",
		CreatedAt:    "x",
	}
	got := FormatRequestOption(r)
	if !strings.Contains(got, "- / -") {
		t.Errorf("expected '- / -' placeholders, got %q", got)
	}
	if !strings.Contains(got, "[short]") {
		t.Errorf("expected short id [short], got %q", got)
	}
}

func TestBuildRequestOptions_SortedByCreatedAtDesc(t *testing.T) {
	reqs := []wfmodels.AccessRequest{
		{RequestID: "a", CreatedAt: "2026-04-01T00:00:00Z"},
		{RequestID: "b", CreatedAt: "2026-04-20T00:00:00Z"},
		{RequestID: "c", CreatedAt: "2026-04-10T00:00:00Z"},
	}
	opts, sorted := BuildRequestOptions(reqs)
	if len(opts) != 3 {
		t.Fatalf("expected 3 options, got %d", len(opts))
	}
	want := []string{"b", "c", "a"}
	for i, id := range want {
		if sorted[i].RequestID != id {
			t.Errorf("position %d: got %q want %q", i, sorted[i].RequestID, id)
		}
	}
}

func TestSelectRequest_NonInteractive(t *testing.T) {
	orig := IsTerminalFunc
	defer func() { IsTerminalFunc = orig }()
	IsTerminalFunc = func(fd uintptr) bool { return false }

	_, err := SelectRequest([]wfmodels.AccessRequest{{RequestID: "r1"}})
	if err == nil {
		t.Fatal("expected error in non-interactive mode")
	}
	if !errors.Is(err, ErrNotInteractive) {
		t.Errorf("expected ErrNotInteractive, got %v", err)
	}
	if !strings.Contains(err.Error(), "positional argument") {
		t.Errorf("error should hint at positional arg: %v", err)
	}
}

func TestBuildRequestOptions_SortedCorrectlyWithOffsets(t *testing.T) {
	// "2026-04-20T10:00:00+02:00" == 08:00 UTC — earlier than 09:30Z
	// String sort would put +02:00 after Z; time sort must put 09:30Z first.
	reqs := []wfmodels.AccessRequest{
		{RequestID: "offset", CreatedAt: "2026-04-20T10:00:00+02:00"}, // 08:00 UTC
		{RequestID: "utc", CreatedAt: "2026-04-20T09:30:00Z"},          // 09:30 UTC (more recent)
	}
	_, sorted := BuildRequestOptions(reqs)
	if sorted[0].RequestID != "utc" {
		t.Errorf("expected utc (09:30Z) first, got %q", sorted[0].RequestID)
	}
	if sorted[1].RequestID != "offset" {
		t.Errorf("expected offset (08:00 UTC) second, got %q", sorted[1].RequestID)
	}
}

func TestSelectRequest_EmptyList(t *testing.T) {
	orig := IsTerminalFunc
	defer func() { IsTerminalFunc = orig }()
	IsTerminalFunc = func(fd uintptr) bool { return true }

	_, err := SelectRequest(nil)
	if err == nil {
		t.Fatal("expected error for empty list")
	}
	if !strings.Contains(err.Error(), "no access requests") {
		t.Errorf("unexpected error: %v", err)
	}
}
