// NOTE: Do not use t.Parallel() in cmd/ tests due to package-level state
// (verbose, passedArgValidation) that is mutated during test execution.
package cmd

import (
	"strings"
	"testing"

	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
)

func TestDedupeSessionIDs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"no duplicates", []string{"a", "b"}, []string{"a", "b"}},
		{"duplicates collapsed, first-seen order kept", []string{"b", "a", "b"}, []string{"b", "a"}},
		{"all duplicates", []string{"a", "a", "a"}, []string{"a"}},
		{"empty", nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedupeSessionIDs(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("dedupeSessionIDs(%v) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("dedupeSessionIDs(%v) = %v, want %v", tt.in, got, tt.want)
				}
			}
		})
	}
}

func TestReconcileRevocations(t *testing.T) {
	ok := func(id string) scamodels.RevocationResult {
		return scamodels.RevocationResult{SessionID: id, RevocationStatus: scamodels.RevocationSuccessful}
	}
	notApplicable := func(id string) scamodels.RevocationResult {
		return scamodels.RevocationResult{SessionID: id, RevocationStatus: scamodels.RevocationNotApplicable}
	}

	tests := []struct {
		name           string
		requested      []string
		results        []scamodels.RevocationResult
		wantRecords    []revocationRecord
		wantUnattached []unattributedResult
		wantReasonSub  map[string]string
	}{
		{
			name:      "exact match",
			requested: []string{"A", "B"},
			results:   []scamodels.RevocationResult{ok("A"), ok("B")},
			wantRecords: []revocationRecord{
				{SessionID: "A", Status: scamodels.RevocationSuccessful, Outcome: scamodels.OutcomeRevoked},
				{SessionID: "B", Status: scamodels.RevocationSuccessful, Outcome: scamodels.OutcomeRevoked},
			},
		},
		{
			name:      "missing row is a failure",
			requested: []string{"A", "B"},
			results:   []scamodels.RevocationResult{ok("A")},
			wantRecords: []revocationRecord{
				{SessionID: "A", Status: scamodels.RevocationSuccessful, Outcome: scamodels.OutcomeRevoked},
				{SessionID: "B", Status: "", Outcome: scamodels.OutcomeUnknown},
			},
			wantReasonSub: map[string]string{"B": "no result returned"},
		},
		{
			name:      "duplicate rows, worst outcome wins",
			requested: []string{"A"},
			results:   []scamodels.RevocationResult{ok("A"), notApplicable("A")},
			wantRecords: []revocationRecord{
				{SessionID: "A", Status: scamodels.RevocationNotApplicable, Outcome: scamodels.OutcomeNotApplicable, Duplicate: true},
			},
		},
		{
			name:      "duplicate rows reversed, later success must not mask failure",
			requested: []string{"A"},
			results:   []scamodels.RevocationResult{notApplicable("A"), ok("A")},
			wantRecords: []revocationRecord{
				{SessionID: "A", Status: scamodels.RevocationNotApplicable, Outcome: scamodels.OutcomeNotApplicable, Duplicate: true},
			},
		},
		{
			name:      "row with empty session ID is unattributable",
			requested: []string{"A"},
			results:   []scamodels.RevocationResult{{SessionID: "", RevocationStatus: scamodels.RevocationSuccessful}},
			wantRecords: []revocationRecord{
				{SessionID: "A", Status: "", Outcome: scamodels.OutcomeUnknown},
			},
			wantUnattached: []unattributedResult{{SessionID: "", Status: scamodels.RevocationSuccessful}},
		},
		{
			name:      "unexpected ID satisfies nothing",
			requested: []string{"A"},
			results:   []scamodels.RevocationResult{ok("A"), ok("Z")},
			wantRecords: []revocationRecord{
				{SessionID: "A", Status: scamodels.RevocationSuccessful, Outcome: scamodels.OutcomeRevoked},
			},
			wantUnattached: []unattributedResult{{SessionID: "Z", Status: scamodels.RevocationSuccessful}},
		},
		{
			name:      "empty response array, all unknown",
			requested: []string{"A", "B"},
			results:   nil,
			wantRecords: []revocationRecord{
				{SessionID: "A", Status: "", Outcome: scamodels.OutcomeUnknown},
				{SessionID: "B", Status: "", Outcome: scamodels.OutcomeUnknown},
			},
		},
		{
			name:      "duplicate in request is deduped",
			requested: []string{"A", "A", "B"},
			results:   []scamodels.RevocationResult{ok("A"), ok("B")},
			wantRecords: []revocationRecord{
				{SessionID: "A", Status: scamodels.RevocationSuccessful, Outcome: scamodels.OutcomeRevoked},
				{SessionID: "B", Status: scamodels.RevocationSuccessful, Outcome: scamodels.OutcomeRevoked},
			},
		},
		{
			name:      "unknown status fails closed",
			requested: []string{"A"},
			results:   []scamodels.RevocationResult{{SessionID: "A", RevocationStatus: "TOTALLY_NEW_STATUS"}},
			wantRecords: []revocationRecord{
				{SessionID: "A", Status: "TOTALLY_NEW_STATUS", Outcome: scamodels.OutcomeUnknown},
			},
			wantReasonSub: map[string]string{"A": "unexpected status"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records, unattached := reconcileRevocations(tt.requested, tt.results)

			if len(records) != len(tt.wantRecords) {
				t.Fatalf("got %d records, want %d: %+v", len(records), len(tt.wantRecords), records)
			}
			for i, want := range tt.wantRecords {
				got := records[i]
				if got.SessionID != want.SessionID || got.Status != want.Status ||
					got.Outcome != want.Outcome || got.Duplicate != want.Duplicate {
					t.Errorf("record[%d] = %+v, want %+v", i, got, want)
				}
				if !got.Outcome.Accepted() && got.Reason == "" {
					t.Errorf("record[%d] (%s) has no reason for a non-accepted outcome", i, got.SessionID)
				}
			}

			for id, sub := range tt.wantReasonSub {
				found := false
				for _, r := range records {
					if r.SessionID == id {
						found = true
						if !strings.Contains(r.Reason, sub) {
							t.Errorf("reason for %s = %q, want substring %q", id, r.Reason, sub)
						}
					}
				}
				if !found {
					t.Errorf("no record for %s", id)
				}
			}

			if len(unattached) != len(tt.wantUnattached) {
				t.Fatalf("got %d unattributed results, want %d: %+v", len(unattached), len(tt.wantUnattached), unattached)
			}
			for i, want := range tt.wantUnattached {
				if unattached[i] != want {
					t.Errorf("unattributed[%d] = %+v, want %+v", i, unattached[i], want)
				}
			}
		})
	}
}

func TestSummarizeRevocations(t *testing.T) {
	tests := []struct {
		name        string
		records     []revocationRecord
		wantRevoked int
		wantPending int
		wantFailed  int
		wantAllOK   bool
	}{
		{
			name: "all revoked",
			records: []revocationRecord{
				{Outcome: scamodels.OutcomeRevoked}, {Outcome: scamodels.OutcomeRevoked},
			},
			wantRevoked: 2, wantAllOK: true,
		},
		{
			name: "in progress counts as accepted but not revoked",
			records: []revocationRecord{
				{Outcome: scamodels.OutcomeRevoked}, {Outcome: scamodels.OutcomeInProgress},
			},
			wantRevoked: 1, wantPending: 1, wantAllOK: true,
		},
		{
			name: "partial fails",
			records: []revocationRecord{
				{Outcome: scamodels.OutcomeRevoked}, {Outcome: scamodels.OutcomeNotApplicable},
			},
			wantRevoked: 1, wantFailed: 1, wantAllOK: false,
		},
		{
			name:       "unknown fails",
			records:    []revocationRecord{{Outcome: scamodels.OutcomeUnknown}},
			wantFailed: 1, wantAllOK: false,
		},
		{
			name:      "no records at all fails",
			records:   nil,
			wantAllOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := summarizeRevocations(tt.records)
			if s.revoked != tt.wantRevoked || s.inProgress != tt.wantPending || s.failed != tt.wantFailed {
				t.Errorf("summary = %+v, want revoked=%d inProgress=%d failed=%d",
					s, tt.wantRevoked, tt.wantPending, tt.wantFailed)
			}
			if s.allAccepted() != tt.wantAllOK {
				t.Errorf("allAccepted() = %v, want %v", s.allAccepted(), tt.wantAllOK)
			}
		})
	}
}
