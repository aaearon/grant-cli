// Package sdkclient holds shared policy applied to idsec-sdk-golang HTTP
// clients before grant's services use them.
package sdkclient

import "github.com/cyberark/idsec-sdk-golang/pkg/common"

// DisableTransientRetry turns off the SDK's automatic transient-failure retry.
//
// idsec-sdk-golang v0.8.1 retries by default — 3 retries on top of the initial
// attempt, so up to 4 requests; 500ms base, 10s cap (idsec_client.go:53-60,
// :375-377) — on two paths, neither of which is safe for grant's
// non-idempotent POSTs:
//
//   - HTTP 429 (idsec_client.go:865-885) — no HTTP method filter at all.
//   - Transport errors (idsec_client.go:835-849 via isRetryableTransportError,
//     :1244-1283) — a bare io.EOF / io.ErrUnexpectedEOF, or an error containing
//     "eof" or "server closed idle connection", is retried for ANY method
//     including POST (:1252-1266). Only connection-reset / broken-pipe / GOAWAY
//     are gated behind isIdempotentMethod (:1269-1281). An EOF can surface
//     after the server already processed the request, so that path can replay a
//     mutation and produce a duplicate.
//
// The SDK exposes no per-request opt-out, and toggling client-wide state around
// individual calls is race-prone (grant fans out concurrently across CSPs), so
// grant disables transient retry on the whole client for both the SCA and
// UAR/workflows services. See idsec_client.go:1187-1197 for SetTransientRetry.
func DisableTransientRetry(c *common.IdsecClient) {
	if c == nil {
		return
	}
	c.SetTransientRetry(0, 0, 0)
}
