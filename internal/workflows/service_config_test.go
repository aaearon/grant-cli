package workflows

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

func TestServiceConfig_ServiceName(t *testing.T) {
	config := ServiceConfig()
	expected := "access-requests"
	if config.ServiceName != expected {
		t.Errorf("expected ServiceName %q, got %q", expected, config.ServiceName)
	}
}

func TestServiceConfig_RequiredAuthenticators(t *testing.T) {
	config := ServiceConfig()
	if len(config.RequiredAuthenticatorNames) != 1 {
		t.Fatalf("expected 1 required authenticator, got %d", len(config.RequiredAuthenticatorNames))
	}
	expected := "isp"
	if config.RequiredAuthenticatorNames[0] != expected {
		t.Errorf("expected required authenticator %q, got %q", expected, config.RequiredAuthenticatorNames[0])
	}
}

func TestServiceConfig_OptionalAuthenticators(t *testing.T) {
	config := ServiceConfig()
	if len(config.OptionalAuthenticatorNames) != 0 {
		t.Errorf("expected 0 optional authenticators, got %d", len(config.OptionalAuthenticatorNames))
	}
}

func TestServiceConfig_ActionsConfigurations(t *testing.T) {
	config := ServiceConfig()
	if config.ActionsConfigurations != nil {
		t.Errorf("expected nil ActionsConfigurations, got %v", config.ActionsConfigurations)
	}
}

func TestServiceConfig_ReturnsIdsecServiceConfig(t *testing.T) {
	config := ServiceConfig()
	// Verify it returns the correct SDK type
	var _ services.IdsecServiceConfig = config
}

// TestNewAccessRequestService_ResolvesISPAuthenticator pins the authenticator
// name the constructor looks up. Asking for anything other than "isp" makes the
// constructor fail outright.
func TestNewAccessRequestService_ResolvesISPAuthenticator(t *testing.T) {
	svc, err := NewAccessRequestService(ispAuthWithToken(t))
	if err != nil {
		t.Fatalf("NewAccessRequestService: %v", err)
	}
	if svc.ispAuth == nil {
		t.Error("ispAuth = nil, want the resolved ISP authenticator")
	}
}

// TestNewAccessRequestService_UsesUARServiceSlug pins the "uar" service slug
// passed to isp.FromISPAuth. The retry test overwrites BaseURL before issuing a
// request, so without this the slug could be changed to anything and no test in
// the repo would notice — while every live request would go to the wrong host.
func TestNewAccessRequestService_UsesUARServiceSlug(t *testing.T) {
	svc, err := NewAccessRequestService(ispAuthWithToken(t))
	if err != nil {
		t.Fatalf("NewAccessRequestService: %v", err)
	}

	// The fake JWT carries subdomain=testtenant, platform_domain=example.test.
	const want = "https://testtenant.uar.example.test"
	if got := ispClientFromService(t, svc).BaseURL; got != want {
		t.Errorf("BaseURL = %q, want %q", got, want)
	}
}

// ispClientFromService reaches through the logging decorator to the SDK client
// the constructor actually published.
func ispClientFromService(t *testing.T, svc *AccessRequestService) *isp.IdsecISPServiceClient {
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
