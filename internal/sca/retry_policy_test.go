package sca

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// fakeJWT builds an unsigned JWT carrying just the claims the SDK's
// resolveServiceURL reads (isp/idsec_isp_service_client.go:148-168). It is
// parsed with ParseUnverified, so no signature is required.
func fakeJWT(t *testing.T) string {
	t.Helper()
	enc := func(v interface{}) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal jwt segment: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]string{"alg": "none", "typ": "JWT"})
	payload := enc(map[string]string{
		"subdomain":       "testtenant",
		"platform_domain": "example.test",
	})
	return header + "." + payload + ".sig"
}

// ispAuthWithToken returns an ISP authenticator pre-loaded with a fake token so
// isp.FromISPAuth succeeds without real credentials.
func ispAuthWithToken(t *testing.T) auth.IdsecAuth {
	t.Helper()
	a := auth.NewIdsecISPAuth(false)
	concrete, ok := a.(*auth.IdsecISPAuth)
	if !ok {
		t.Fatalf("NewIdsecISPAuth returned %T, want *auth.IdsecISPAuth", a)
	}
	concrete.Token = &authmodels.IdsecToken{
		Token:     fakeJWT(t),
		TokenType: authmodels.JWT,
	}
	return a
}

// TestNewSCAAccessServiceDisablesTransientRetry exercises the real constructor
// and asserts the policy landed on the client it publishes. This is the
// regression guard for the DisableTransientRetry call in NewSCAAccessService:
// deleting that call makes this test fail with 4 inbound requests.
func TestNewSCAAccessServiceDisablesTransientRetry(t *testing.T) {
	var calls int32
	var gotAPIVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		gotAPIVersion = r.Header.Get("X-API-Version")
		w.Header().Set("Retry-After", "0") // keeps the test fast if retry is on
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	svc, err := NewSCAAccessService(ispAuthWithToken(t))
	if err != nil {
		t.Fatalf("NewSCAAccessService: %v", err)
	}

	// Redirect the constructed client at the test server. The client is fully
	// built by the constructor; only its base URL is swapped.
	lc, ok := svc.httpClient.(*loggingClient)
	if !ok {
		t.Fatalf("httpClient is %T, want *loggingClient", svc.httpClient)
	}
	client, ok := lc.inner.(*isp.IdsecISPServiceClient)
	if !ok {
		t.Fatalf("inner client is %T, want *isp.IdsecISPServiceClient", lc.inner)
	}
	client.BaseURL = srv.URL

	resp, err := svc.httpClient.Post(t.Context(), "/api/access/elevate", map[string]string{"a": "b"})
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("inbound requests = %d, want 1 (SDK transient retry must be disabled)", got)
	}
	if gotAPIVersion != "2.0" {
		t.Errorf("X-API-Version = %q, want %q", gotAPIVersion, "2.0")
	}
}
