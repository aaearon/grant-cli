package cmd

import (
	"context"

	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
)

// chunkSessionIDs splits ids into consecutive slices of at most size,
// preserving order.
func chunkSessionIDs(ids []string, size int) [][]string {
	if len(ids) == 0 || size <= 0 {
		return nil
	}
	chunks := make([][]string, 0, (len(ids)+size-1)/size)
	for start := 0; start < len(ids); start += size {
		end := start + size
		if end > len(ids) {
			end = len(ids)
		}
		chunks = append(chunks, ids[start:end])
	}
	return chunks
}

// revokeInBatches revokes ids in sequential batches of at most
// scamodels.MaxRevokeBatchSize, the API's cap on the request body.
//
// On a batch failure it returns the results already collected together with the
// error, so outcomes from earlier batches are never discarded: aborting
// silently would under-report revocations that actually happened.
func revokeInBatches(ctx context.Context, revoker sessionRevoker, ids []string) ([]scamodels.RevocationResult, error) {
	var results []scamodels.RevocationResult

	for _, chunk := range chunkSessionIDs(ids, scamodels.MaxRevokeBatchSize) {
		batchCtx, cancel := context.WithTimeout(ctx, apiTimeout)
		resp, err := revoker.RevokeSessions(batchCtx, &scamodels.RevokeRequest{SessionIDs: chunk})
		cancel()
		if err != nil {
			return results, err
		}
		if resp != nil {
			results = append(results, resp.Response...)
		}
	}

	return results, nil
}
