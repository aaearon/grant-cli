// NOTE: Do not use t.Parallel() in cmd/ tests due to package-level state
// (verbose, passedArgValidation) that is mutated during test execution.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"testing"

	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
)

func makeSessionIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("s%03d", i)
	}
	return ids
}

func TestChunkSessionIDs(t *testing.T) {
	tests := []struct {
		name       string
		count      int
		wantChunks []int
	}{
		{"empty", 0, nil},
		{"single", 1, []int{1}},
		{"exactly one full batch", 100, []int{100}},
		{"one over a batch", 101, []int{100, 1}},
		{"two and a half batches", 250, []int{100, 100, 50}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids := makeSessionIDs(tt.count)
			chunks := chunkSessionIDs(ids, scamodels.MaxRevokeBatchSize)

			if len(chunks) != len(tt.wantChunks) {
				t.Fatalf("got %d chunks, want %d", len(chunks), len(tt.wantChunks))
			}

			var flat []string
			for i, c := range chunks {
				if len(c) != tt.wantChunks[i] {
					t.Errorf("chunk[%d] size = %d, want %d", i, len(c), tt.wantChunks[i])
				}
				if len(c) > scamodels.MaxRevokeBatchSize {
					t.Errorf("chunk[%d] exceeds the API limit: %d", i, len(c))
				}
				flat = append(flat, c...)
			}

			if len(flat) != len(ids) {
				t.Fatalf("flattened chunks have %d IDs, want %d", len(flat), len(ids))
			}
			for i := range ids {
				if flat[i] != ids[i] {
					t.Fatalf("order not preserved at %d: got %q, want %q", i, flat[i], ids[i])
				}
			}
		})
	}
}

func TestRevokeInBatches_AggregatesAcrossChunks(t *testing.T) {
	ids := makeSessionIDs(250)

	revoker := &mockSessionRevoker{
		revokeFunc: func(ctx context.Context, req *scamodels.RevokeRequest) (*scamodels.RevokeResponse, error) {
			results := make([]scamodels.RevocationResult, len(req.SessionIDs))
			for i, id := range req.SessionIDs {
				results[i] = scamodels.RevocationResult{SessionID: id, RevocationStatus: scamodels.RevocationSuccessful}
			}
			return &scamodels.RevokeResponse{Response: results}, nil
		},
	}

	results, err := revokeInBatches(t.Context(), revoker, ids)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(revoker.calls) != 3 {
		t.Fatalf("got %d revoke calls, want 3", len(revoker.calls))
	}
	for i, call := range revoker.calls {
		if len(call) > scamodels.MaxRevokeBatchSize {
			t.Errorf("call[%d] sent %d IDs, exceeding the API limit", i, len(call))
		}
	}
	if len(results) != 250 {
		t.Fatalf("got %d results, want 250", len(results))
	}
	for i, r := range results {
		if r.SessionID != ids[i] {
			t.Fatalf("result[%d] = %q, want %q", i, r.SessionID, ids[i])
		}
	}
}

func TestRevokeInBatches_SingleBatch(t *testing.T) {
	revoker := &mockSessionRevoker{
		response: &scamodels.RevokeResponse{Response: []scamodels.RevocationResult{
			{SessionID: "s000", RevocationStatus: scamodels.RevocationSuccessful},
		}},
	}

	results, err := revokeInBatches(t.Context(), revoker, makeSessionIDs(1))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(revoker.calls) != 1 {
		t.Fatalf("got %d revoke calls, want 1", len(revoker.calls))
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
}

func TestRevokeInBatches_ErrorMidSequenceKeepsEarlierResults(t *testing.T) {
	ids := makeSessionIDs(250)
	boom := errors.New("service unavailable")

	call := 0
	revoker := &mockSessionRevoker{
		revokeFunc: func(ctx context.Context, req *scamodels.RevokeRequest) (*scamodels.RevokeResponse, error) {
			call++
			if call == 2 {
				return nil, boom
			}
			results := make([]scamodels.RevocationResult, len(req.SessionIDs))
			for i, id := range req.SessionIDs {
				results[i] = scamodels.RevocationResult{SessionID: id, RevocationStatus: scamodels.RevocationSuccessful}
			}
			return &scamodels.RevokeResponse{Response: results}, nil
		},
	}

	results, err := revokeInBatches(t.Context(), revoker, ids)
	if err == nil {
		t.Fatal("expected an error from the failing batch")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want it to wrap %v", err, boom)
	}
	// Chunk 1's outcomes must survive; aborting silently would under-report
	// revocations that actually happened.
	if len(results) != 100 {
		t.Fatalf("got %d results, want the 100 from the first batch", len(results))
	}
	if call != 2 {
		t.Errorf("made %d calls, want 2 (stop after the failure)", call)
	}
}

func TestRevokeInBatches_NilResponseIsNotASuccess(t *testing.T) {
	revoker := &mockSessionRevoker{}

	results, err := revokeInBatches(t.Context(), revoker, makeSessionIDs(2))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("got %d results, want 0", len(results))
	}

	// Reconciliation must then report both requested sessions as unknown.
	records, _ := reconcileRevocations(makeSessionIDs(2), results)
	if summarizeRevocations(records).allAccepted() {
		t.Error("a nil response must not be reconciled as success")
	}
}
