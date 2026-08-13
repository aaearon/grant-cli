package k8s

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sdkk8s "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// stubBackend is a hand-written double for the SDK k8s service.
type stubBackend struct {
	listFn     func(*k8smodels.IdsecSCAk8sListClustersRequest) (*k8smodels.IdsecSCAk8sListClustersResponse, error)
	evaluateFn func(*k8smodels.IdsecSCAK8sEvaluateRequest, string) (*k8smodels.IdsecSCAK8sEvaluateResponse, error)
	elevateFn  func(*k8smodels.IdsecSCAK8sElevateKubectlRequest) (*k8smodels.IdsecSCAK8sElevateResponse, error)
	kubecfgFn  func(context.Context, []string, string) *k8smodels.IdsecSCAK8sGenerateKubeconfigParallelResponse
	proxyFn    func(string, *sdkk8s.IdsecSCAK8sClusterContext) (*k8smodels.IdsecSCAK8sExecCredential, error)
}

func (s *stubBackend) ListTargets(req *k8smodels.IdsecSCAk8sListClustersRequest) (*k8smodels.IdsecSCAk8sListClustersResponse, error) {
	if s.listFn != nil {
		return s.listFn(req)
	}
	return &k8smodels.IdsecSCAk8sListClustersResponse{}, nil
}

func (s *stubBackend) EvaluateEligibility(req *k8smodels.IdsecSCAK8sEvaluateRequest, csp string) (*k8smodels.IdsecSCAK8sEvaluateResponse, error) {
	if s.evaluateFn != nil {
		return s.evaluateFn(req, csp)
	}
	return &k8smodels.IdsecSCAK8sEvaluateResponse{}, nil
}

func (s *stubBackend) Elevate(req *k8smodels.IdsecSCAK8sElevateKubectlRequest) (*k8smodels.IdsecSCAK8sElevateResponse, error) {
	if s.elevateFn != nil {
		return s.elevateFn(req)
	}
	return &k8smodels.IdsecSCAK8sElevateResponse{}, nil
}

func (s *stubBackend) GenerateKubeconfigParallel(ctx context.Context, csps []string, loc string) *k8smodels.IdsecSCAK8sGenerateKubeconfigParallelResponse {
	if s.kubecfgFn != nil {
		return s.kubecfgFn(ctx, csps, loc)
	}
	return &k8smodels.IdsecSCAK8sGenerateKubeconfigParallelResponse{}
}

func (s *stubBackend) GenerateProxyExecCredential(csp string, cctx *sdkk8s.IdsecSCAK8sClusterContext) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	if s.proxyFn != nil {
		return s.proxyFn(csp, cctx)
	}
	return &k8smodels.IdsecSCAK8sExecCredential{}, nil
}

func strptr(s string) *string { return &s }

func TestNormalizeCSP(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "aws lowercase", in: "aws", want: "AWS"},
		{name: "azure mixed case", in: "AzUrE", want: "AZURE"},
		{name: "trims whitespace", in: "  aws  ", want: "AWS"},
		{name: "empty is invalid", in: "", wantErr: true},
		{name: "gcp unsupported", in: "gcp", wantErr: true},
		{name: "garbage", in: "nope", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeCSP(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NormalizeCSP(%q) = %q, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("NormalizeCSP(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestServiceListClusters(t *testing.T) {
	resp := &k8smodels.IdsecSCAk8sListClustersResponse{
		Total: 1,
		Response: []k8smodels.IdsecSCAk8sListClustersEligibleTarget{
			{
				OrganizationID: strptr("o-123"),
				WorkspaceID:    "111122223333",
				WorkspaceName:  "prod-account",
				WorkspaceType:  "ACCOUNT",
				Role:           k8smodels.IdsecSCAk8sListClustersRole{ID: "arn:aws:iam::1:role/admin", Name: "admin"},
				Target: k8smodels.IdsecSCAk8sListClustersTarget{
					Scope:     "cluster",
					Region:    "us-east-1",
					ClusterID: "arn:aws:eks:us-east-1:1:cluster/prod",
					FQDN:      strptr("abc.gr7.us-east-1.eks.amazonaws.com"),
				},
			},
		},
	}

	var gotReq *k8smodels.IdsecSCAk8sListClustersRequest
	svc := NewServiceWithBackend(&stubBackend{
		listFn: func(r *k8smodels.IdsecSCAk8sListClustersRequest) (*k8smodels.IdsecSCAk8sListClustersResponse, error) {
			gotReq = r
			return resp, nil
		},
	})

	clusters, err := svc.ListClusters(t.Context(), "aws")
	if err != nil {
		t.Fatalf("ListClusters: %v", err)
	}
	if gotReq.CSP != "AWS" || gotReq.All {
		t.Errorf("request = %+v, want CSP=AWS All=false", gotReq)
	}
	if len(clusters) != 1 {
		t.Fatalf("got %d clusters, want 1", len(clusters))
	}
	c := clusters[0]
	if c.Provider != "aws" {
		t.Errorf("Provider = %q, want aws", c.Provider)
	}
	if c.Name != "prod" {
		t.Errorf("Name = %q, want prod (derived from cluster ARN)", c.Name)
	}
	if c.FQDN != "abc.gr7.us-east-1.eks.amazonaws.com" {
		t.Errorf("FQDN = %q", c.FQDN)
	}
	if c.OrganizationID != "o-123" {
		t.Errorf("OrganizationID = %q, want o-123", c.OrganizationID)
	}
	if c.RoleID != "arn:aws:iam::1:role/admin" || c.RoleName != "admin" {
		t.Errorf("role = %q/%q", c.RoleID, c.RoleName)
	}
}

func TestServiceListClustersAllCSPs(t *testing.T) {
	svc := NewServiceWithBackend(&stubBackend{
		listFn: func(r *k8smodels.IdsecSCAk8sListClustersRequest) (*k8smodels.IdsecSCAk8sListClustersResponse, error) {
			if !r.All {
				t.Errorf("expected All=true when csp is empty, got %+v", r)
			}
			return &k8smodels.IdsecSCAk8sListClustersResponse{
				Responses: map[string]k8smodels.IdsecSCAk8sListClustersResponse{
					"aws": {Response: []k8smodels.IdsecSCAk8sListClustersEligibleTarget{
						{WorkspaceName: "acct", Target: k8smodels.IdsecSCAk8sListClustersTarget{ClusterID: "c1"}},
					}},
					"azure": {Response: []k8smodels.IdsecSCAk8sListClustersEligibleTarget{
						{WorkspaceName: "sub", Target: k8smodels.IdsecSCAk8sListClustersTarget{ClusterID: "c2"}},
					}},
				},
			}, nil
		},
	})

	clusters, err := svc.ListClusters(t.Context(), "")
	if err != nil {
		t.Fatalf("ListClusters: %v", err)
	}
	if len(clusters) != 2 {
		t.Fatalf("got %d clusters, want 2 (merged across CSPs)", len(clusters))
	}
	seen := map[string]bool{}
	for _, c := range clusters {
		seen[c.Provider] = true
	}
	if !seen["aws"] || !seen["azure"] {
		t.Errorf("expected both providers, got %v", seen)
	}
}

func TestServiceListClustersInvalidCSP(t *testing.T) {
	svc := NewServiceWithBackend(&stubBackend{})
	if _, err := svc.ListClusters(t.Context(), "gcp"); err == nil {
		t.Fatal("expected error for unsupported CSP")
	}
}

func TestServiceListClustersWrapsSDKError(t *testing.T) {
	sentinel := errors.New("boom")
	svc := NewServiceWithBackend(&stubBackend{
		listFn: func(*k8smodels.IdsecSCAk8sListClustersRequest) (*k8smodels.IdsecSCAk8sListClustersResponse, error) {
			return nil, sentinel
		},
	})

	_, err := svc.ListClusters(t.Context(), "aws")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error does not wrap the SDK error: %v", err)
	}
	if !strings.Contains(err.Error(), "list clusters") {
		t.Errorf("error lacks grant-shaped context: %v", err)
	}
}

// The SDK's ListTargets takes no context, so grant enforces cancellation itself.
func TestServiceListClustersHonoursCancelledContext(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	svc := NewServiceWithBackend(&stubBackend{
		listFn: func(*k8smodels.IdsecSCAk8sListClustersRequest) (*k8smodels.IdsecSCAk8sListClustersResponse, error) {
			<-release
			return &k8smodels.IdsecSCAk8sListClustersResponse{}, nil
		},
	})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := svc.ListClusters(ctx, "aws"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// GenerateKubeconfigParallel is the one SDK entry point that accepts a context;
// grant passes the caller's context straight through.
func TestServiceGenerateKubeconfigsPropagatesContext(t *testing.T) {
	var gotCtx context.Context
	svc := NewServiceWithBackend(&stubBackend{
		kubecfgFn: func(ctx context.Context, csps []string, loc string) *k8smodels.IdsecSCAK8sGenerateKubeconfigParallelResponse {
			gotCtx = ctx
			return &k8smodels.IdsecSCAK8sGenerateKubeconfigParallelResponse{
				Succeeded: []k8smodels.IdsecSCAK8sKubeconfigOutcome{{CSP: "aws", Kubeconfig: "apiVersion: v1"}},
				Failed:    []k8smodels.IdsecSCAK8sKubeconfigOutcome{{CSP: "azure", Error: "nope"}},
			}
		},
	})

	type ctxKey string
	ctx := context.WithValue(t.Context(), ctxKey("marker"), "yes")

	ok, failed, err := svc.GenerateKubeconfigs(ctx, []string{"aws", "azure"})
	if err != nil {
		t.Fatalf("GenerateKubeconfigs: %v", err)
	}
	if gotCtx == nil || gotCtx.Value(ctxKey("marker")) != "yes" {
		t.Error("caller context was not propagated to GenerateKubeconfigParallel")
	}
	if len(ok) != 1 || ok["aws"] != "apiVersion: v1" {
		t.Errorf("succeeded = %v", ok)
	}
	if len(failed) != 1 || failed[0].CSP != "azure" {
		t.Errorf("failed = %v", failed)
	}
}

func TestServiceGenerateKubeconfigsValidatesCSPs(t *testing.T) {
	svc := NewServiceWithBackend(&stubBackend{})
	if _, _, err := svc.GenerateKubeconfigs(t.Context(), []string{"gcp"}); err == nil {
		t.Fatal("expected error for unsupported CSP")
	}
	if _, _, err := svc.GenerateKubeconfigs(t.Context(), nil); err == nil {
		t.Fatal("expected error for empty CSP list")
	}
}

func TestServiceEvaluate(t *testing.T) {
	svc := NewServiceWithBackend(&stubBackend{
		evaluateFn: func(req *k8smodels.IdsecSCAK8sEvaluateRequest, csp string) (*k8smodels.IdsecSCAK8sEvaluateResponse, error) {
			if csp != "AWS" {
				t.Errorf("csp = %q, want AWS", csp)
			}
			if len(req.Targets) != 1 || req.Targets[0].FQDN != "host" {
				t.Errorf("targets = %+v", req.Targets)
			}
			return &k8smodels.IdsecSCAK8sEvaluateResponse{
				Response: []k8smodels.IdsecSCAK8sEvaluateResult{{
					ConnectionMethod: "proxy",
					CertificateData:  "Y2E=",
					WorkspaceID:      "ws",
					Role:             k8smodels.IdsecSCAk8sListClustersRole{ID: "r"},
					Target:           k8smodels.IdsecSCAk8sListClustersTarget{ClusterID: "cid", Region: "us-east-1"},
				}},
			}, nil
		},
	})

	got, err := svc.Evaluate(t.Context(), "aws", "host")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.ConnectionMethod != ConnectionProxy {
		t.Errorf("ConnectionMethod = %q, want proxy", got.ConnectionMethod)
	}
	if got.CertificateData != "Y2E=" {
		t.Errorf("CertificateData = %q", got.CertificateData)
	}
}

func TestServiceEvaluateNoResults(t *testing.T) {
	svc := NewServiceWithBackend(&stubBackend{
		evaluateFn: func(*k8smodels.IdsecSCAK8sEvaluateRequest, string) (*k8smodels.IdsecSCAK8sEvaluateResponse, error) {
			return &k8smodels.IdsecSCAK8sEvaluateResponse{}, nil
		},
	})
	_, err := svc.Evaluate(t.Context(), "aws", "host")
	if err == nil || !strings.Contains(err.Error(), "not eligible") {
		t.Fatalf("err = %v, want a not-eligible error", err)
	}
}

func TestServiceElevate(t *testing.T) {
	svc := NewServiceWithBackend(&stubBackend{
		elevateFn: func(req *k8smodels.IdsecSCAK8sElevateKubectlRequest) (*k8smodels.IdsecSCAK8sElevateResponse, error) {
			if req.CSP != "AWS" || req.FQDN != "host" || req.RoleID != "role" {
				t.Errorf("req = %+v", req)
			}
			return &k8smodels.IdsecSCAK8sElevateResponse{
				Response: k8smodels.IdsecSCAK8sElevateResponseBody{
					CSP: "AWS",
					Results: []k8smodels.IdsecSCAK8sElevateResult{{
						SessionID: "s1", RoleName: "admin", TargetID: "arn:aws:eks:us-east-1:1:cluster/prod",
						SessionExpTime: "2026-08-13T10:00:00Z",
					}},
				},
			}, nil
		},
	})

	res, err := svc.Elevate(t.Context(), ElevateParams{CSP: "aws", FQDN: "host", RoleID: "role"})
	if err != nil {
		t.Fatalf("Elevate: %v", err)
	}
	if res.SessionID != "s1" || res.RoleName != "admin" {
		t.Errorf("result = %+v", res)
	}
}

func TestServiceElevateEmptyResults(t *testing.T) {
	svc := NewServiceWithBackend(&stubBackend{
		elevateFn: func(*k8smodels.IdsecSCAK8sElevateKubectlRequest) (*k8smodels.IdsecSCAK8sElevateResponse, error) {
			return &k8smodels.IdsecSCAK8sElevateResponse{}, nil
		},
	})
	if _, err := svc.Elevate(t.Context(), ElevateParams{CSP: "aws", FQDN: "h", RoleID: "r"}); err == nil {
		t.Fatal("expected error when elevate returns no results")
	}
}

func TestServiceElevateRequiresFields(t *testing.T) {
	svc := NewServiceWithBackend(&stubBackend{})
	tests := []struct {
		name string
		p    ElevateParams
	}{
		{name: "missing fqdn", p: ElevateParams{CSP: "aws", RoleID: "r"}},
		{name: "missing role", p: ElevateParams{CSP: "aws", FQDN: "h"}},
		{name: "bad csp", p: ElevateParams{CSP: "gcp", FQDN: "h", RoleID: "r"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := svc.Elevate(t.Context(), tt.p); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestClusterDisplayName(t *testing.T) {
	tests := []struct {
		name string
		in   Cluster
		want string
	}{
		{name: "eks arn", in: Cluster{ClusterID: "arn:aws:eks:us-east-1:1:cluster/prod"}, want: "prod"},
		{name: "azure resource id", in: Cluster{ClusterID: "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks1"}, want: "aks1"},
		{name: "plain name", in: Cluster{ClusterID: "plain"}, want: "plain"},
		{name: "empty falls back to fqdn", in: Cluster{FQDN: "host.example"}, want: "host.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clusterDisplayName(tt.in.ClusterID, tt.in.FQDN); got != tt.want {
				t.Errorf("clusterDisplayName = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRunWithContextReturnsResult(t *testing.T) {
	got, err := runWithContext(t.Context(), func() (int, error) {
		time.Sleep(time.Millisecond)
		return 42, nil
	})
	if err != nil || got != 42 {
		t.Fatalf("got %d, %v", got, err)
	}
}
