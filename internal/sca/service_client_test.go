package sca

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
)

// ispClientFromService reaches through the logging decorator to the SDK client
// the constructor actually published.
func ispClientFromService(t *testing.T, svc *SCAAccessService) *isp.IdsecISPServiceClient {
	t.Helper()
	lc, ok := svc.httpClient.(*loggingClient)
	if !ok {
		t.Fatalf("httpClient is %T, want *loggingClient", svc.httpClient)
	}
	client, ok := lc.inner.(*isp.IdsecISPServiceClient)
	if !ok {
		t.Fatalf("inner client is %T, want *isp.IdsecISPServiceClient", lc.inner)
	}
	return client
}

// TestNewSCAAccessService_SetsAPIVersionHeader is the standalone guard for the
// X-API-Version header. It previously existed only as two lines inside
// TestNewSCAAccessServiceDisablesTransientRetry, so any retry-motivated rename
// or deletion of that test would have removed the header guard silently.
func TestNewSCAAccessService_SetsAPIVersionHeader(t *testing.T) {
	gotAPIVersion := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIVersion <- r.Header.Get("X-API-Version")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	svc, err := NewSCAAccessService(ispAuthWithToken(t))
	if err != nil {
		t.Fatalf("NewSCAAccessService: %v", err)
	}
	ispClientFromService(t, svc).BaseURL = srv.URL

	resp, err := svc.httpClient.Get(t.Context(), "/api/access/sessions", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := <-gotAPIVersion; got != "2.0" {
		t.Errorf("X-API-Version = %q, want %q", got, "2.0")
	}
}

// TestNewSCAAccessService_UsesSCAServiceSlug pins the "sca" service slug passed
// to isp.FromISPAuth. The retry and header tests both overwrite BaseURL before
// issuing a request, so without this the slug could be changed to anything and
// no test in the repo would notice — while every live request would go to the
// wrong host.
func TestNewSCAAccessService_UsesSCAServiceSlug(t *testing.T) {
	svc, err := NewSCAAccessService(ispAuthWithToken(t))
	if err != nil {
		t.Fatalf("NewSCAAccessService: %v", err)
	}

	// The fake JWT carries subdomain=testtenant, platform_domain=example.test.
	const want = "https://testtenant.sca.example.test"
	if got := ispClientFromService(t, svc).BaseURL; got != want {
		t.Errorf("BaseURL = %q, want %q", got, want)
	}
}
