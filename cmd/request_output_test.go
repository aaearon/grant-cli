package cmd

// Access-request output field mappings.
//
// Fixture values are deliberately distinct and self-describing; see the header
// of output_contract_test.go for why that is mandatory rather than cosmetic.

import (
	"strings"
	"testing"

	wfmodels "github.com/aaearon/grant-cli/internal/workflows/models"
)

// requestFixture is one fully-populated access request. Every detail value is
// unique so a mapping swap (target with role, createdBy with updatedBy,
// timeFrom with timeTo) changes the rendered output.
func requestFixture() *wfmodels.AccessRequest {
	return &wfmodels.AccessRequest{
		RequestID:      "req-id",
		TargetCategory: "CLOUD_CONSOLE",
		RequestState:   wfmodels.RequestStatePending,
		RequestResult:  wfmodels.RequestResultUnknown,
		RequestLink:    "https://example.test/req-id",
		RequestDetails: map[string]interface{}{
			"locationType":  "provider-fixture",
			"workspaceName": "ws-name",
			"roleName":      "role-name",
			"reason":        "reason-fixture",
			"priority":      "priority-fixture",
			"requestDate":   "2026-04-21",
			"timezone":      "tz-fixture",
			"timeFrom":      "01:11",
			"timeTo":        "22:22",
		},
		FinalizationReason: "finalization-fixture",
		CreatedBy:          "creator-fixture",
		CreatedAt:          "2026-04-20T10:00:00Z",
		UpdatedBy:          "updater-fixture",
		UpdatedAt:          "2026-04-21T11:00:00Z",
	}
}

// TestRequestList_TextFieldMapping pins the TARGET and ROLE columns of the
// `grant request list` table to their respective request details. Swapping the
// two Fprintf arguments produced an equally plausible-looking table.
func TestRequestList_TextFieldMapping(t *testing.T) {
	svc := &mockAccessRequestService{
		listItems:      []wfmodels.AccessRequest{*requestFixture()},
		listTotalCount: 1,
	}

	root := newTestRootCommand()
	root.AddCommand(NewRequestCommandWithDeps(svc))

	out, err := executeCommand(root, "request", "list")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, out)
	}

	var row string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "req-id") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatalf("no data row for req-id in output:\n%s", out)
	}

	// Columns: ID STATE RESULT TARGET ROLE PRIORITY CREATED BY CREATED AT.
	// No fixture value contains a space, so field positions are unambiguous.
	fields := strings.Fields(row)
	// Guard on 7, the highest index read below: a short row must Fatal here
	// rather than panic, which would abort the whole cmd test binary.
	if len(fields) < 7 {
		t.Fatalf("row has %d columns, want at least 7: %q", len(fields), row)
	}
	if fields[3] != "ws-name" {
		t.Errorf("TARGET column = %q, want ws-name", fields[3])
	}
	if fields[4] != "role-name" {
		t.Errorf("ROLE column = %q, want role-name", fields[4])
	}
	if fields[5] != "priority-fixture" {
		t.Errorf("PRIORITY column = %q, want priority-fixture", fields[5])
	}
	if fields[6] != "creator-fixture" {
		t.Errorf("CREATED BY column = %q, want creator-fixture", fields[6])
	}
}

// TestRequestGet_TextFieldMapping pins the created/updated attribution in the
// `grant request get` detail view. Sourcing "Created By" from UpdatedBy
// survived: both fields were "user@test" in the existing fixtures.
func TestRequestGet_TextFieldMapping(t *testing.T) {
	svc := &mockAccessRequestService{getResult: requestFixture()}

	root := newTestRootCommand()
	root.AddCommand(NewRequestCommandWithDeps(svc))

	out, err := executeCommand(root, "request", "get", "req-id")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, out)
	}

	for _, want := range []string{
		"Created By:    creator-fixture",
		"Updated By:    updater-fixture",
		"Created At:    2026-04-20T10:00:00Z",
		"Updated At:    2026-04-21T11:00:00Z",
		"Target:        ws-name",
		"Role:          role-name",
		"Time From:     01:11",
		"Time To:       22:22",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q, got:\n%s", want, out)
		}
	}
}

// TestRequestGetJSON_FieldMapping is the whole-object contract for the access
// request document, shared by `request get`, `submit`, `cancel`, `approve` and
// `reject`. Swapping timeFrom with timeTo survived every existing test.
func TestRequestGetJSON_FieldMapping(t *testing.T) {
	svc := &mockAccessRequestService{getResult: requestFixture()}

	root := newTestRootCommand()
	root.AddCommand(NewRequestCommandWithDeps(svc))

	stdout, stderr, err := executeCommandStreams(root, "request", "get", "req-id", "--output", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	assertJSONEqual(t, []byte(stdout), `{
  "requestId": "req-id",
  "targetCategory": "CLOUD_CONSOLE",
  "state": "PENDING",
  "result": "UNKNOWN",
  "priority": "priority-fixture",
  "reason": "reason-fixture",
  "provider": "provider-fixture",
  "target": "ws-name",
  "role": "role-name",
  "requestDate": "2026-04-21",
  "timezone": "tz-fixture",
  "timeFrom": "01:11",
  "timeTo": "22:22",
  "finalizationReason": "finalization-fixture",
  "requestLink": "https://example.test/req-id",
  "createdBy": "creator-fixture",
  "createdAt": "2026-04-20T10:00:00Z",
  "updatedBy": "updater-fixture",
  "updatedAt": "2026-04-21T11:00:00Z"
}`)
}
