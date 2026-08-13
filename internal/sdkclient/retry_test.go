package sdkclient

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

// TestDisableTransientRetry verifies that DisableTransientRetry stops the SDK
// from replaying a POST. The SDK's 429 branch (idsec_client.go:865-885) has no
// HTTP method filter, so without the opt-out a non-idempotent POST is sent
// defaultTransientRetryCount+1 times (idsec_client.go:53-60).
func TestDisableTransientRetry(t *testing.T) {
	tests := []struct {
		name         string
		disable      bool
		retryAfter   string
		wantRequests int32
	}{
		{
			name:         "default client replays a rate-limited POST",
			disable:      false,
			retryAfter:   "0", // keeps the test fast; delay parsing is SDK-tested
			wantRequests: 4,   // initial attempt + 3 transient retries
		},
		{
			name:         "disabled client issues exactly one POST",
			disable:      true,
			retryAfter:   "1",
			wantRequests: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				atomic.AddInt32(&calls, 1)
				w.Header().Set("Retry-After", tt.retryAfter)
				w.WriteHeader(http.StatusTooManyRequests)
			}))
			defer srv.Close()

			client := common.NewSimpleIdsecClient(srv.URL)
			if tt.disable {
				DisableTransientRetry(client)
			}

			resp, err := client.Post(t.Context(), "/api/thing", map[string]string{"a": "b"})
			if err != nil {
				t.Fatalf("Post returned error: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusTooManyRequests {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
			}
			if got := atomic.LoadInt32(&calls); got != tt.wantRequests {
				t.Errorf("inbound requests = %d, want %d", got, tt.wantRequests)
			}
		})
	}
}

// TestDisableTransientRetryNilClient guards the call sites, which pass an
// embedded *common.IdsecClient that could in principle be nil.
func TestDisableTransientRetryNilClient(t *testing.T) {
	DisableTransientRetry(nil) // must not panic
}
