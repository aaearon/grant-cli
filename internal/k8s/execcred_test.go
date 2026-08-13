package k8s

import (
	"errors"
	"strings"
	"testing"

	sdkk8s "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

type stubFlow struct {
	directFn func(*ElevateResult, *sdkk8s.IdsecSCAK8sClusterContext, bool) (*k8smodels.IdsecSCAK8sExecCredential, error)
	proxyFn  func(*ElevateResult, *sdkk8s.IdsecSCAK8sClusterContext, bool) (string, error)
}

func (s *stubFlow) Direct(res *ElevateResult, cctx *sdkk8s.IdsecSCAK8sClusterContext, interactive bool) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	if s.directFn != nil {
		return s.directFn(res, cctx, interactive)
	}
	return &k8smodels.IdsecSCAK8sExecCredential{Kind: "ExecCredential"}, nil
}

func (s *stubFlow) ProxyToken(res *ElevateResult, cctx *sdkk8s.IdsecSCAK8sClusterContext, interactive bool) (string, error) {
	if s.proxyFn != nil {
		return s.proxyFn(res, cctx, interactive)
	}
	return "", nil
}

func evaluateBackend(method, certData string) *stubBackend {
	return &stubBackend{
		evaluateFn: func(*k8smodels.IdsecSCAK8sEvaluateRequest, string) (*k8smodels.IdsecSCAK8sEvaluateResponse, error) {
			return &k8smodels.IdsecSCAK8sEvaluateResponse{
				Response: []k8smodels.IdsecSCAK8sEvaluateResult{{
					ConnectionMethod: method,
					CertificateData:  certData,
					Role:             k8smodels.IdsecSCAk8sListClustersRole{ID: "role-from-evaluate"},
					Target: k8smodels.IdsecSCAk8sListClustersTarget{
						ClusterID: "cluster-id", Region: "eu-west-1",
					},
				}},
			}, nil
		},
		elevateFn: func(*k8smodels.IdsecSCAK8sElevateKubectlRequest) (*k8smodels.IdsecSCAK8sElevateResponse, error) {
			return &k8smodels.IdsecSCAK8sElevateResponse{
				Response: k8smodels.IdsecSCAK8sElevateResponseBody{
					CSP: "AWS",
					Results: []k8smodels.IdsecSCAK8sElevateResult{{
						SessionID: "s1",
						TargetID:  "arn:aws:eks:us-east-1:1:cluster/prod",
					}},
				},
			}, nil
		},
	}
}

func TestExecCredentialDirectFlow(t *testing.T) {
	var gotCtx *sdkk8s.IdsecSCAK8sClusterContext
	svc := NewServiceWithBackend(evaluateBackend(ConnectionDirect, "Y2E="))
	svc.SetCredentialFlow(&stubFlow{
		directFn: func(_ *ElevateResult, cctx *sdkk8s.IdsecSCAK8sClusterContext, _ bool) (*k8smodels.IdsecSCAK8sExecCredential, error) {
			gotCtx = cctx
			return &k8smodels.IdsecSCAK8sExecCredential{
				Kind:   "ExecCredential",
				Status: k8smodels.IdsecSCAK8sExecCredentialStatus{Token: "tok"},
			}, nil
		},
	})

	cred, err := svc.ExecCredential(t.Context(), ExecCredentialParams{
		CSP: "aws", FQDN: "prod.eks.example", Interactive: true,
	})
	if err != nil {
		t.Fatalf("ExecCredential: %v", err)
	}
	if cred.Status.Token != "tok" {
		t.Errorf("token = %q", cred.Status.Token)
	}

	// AWS cluster id and region come from the elevate targetId ARN, not evaluate.
	if gotCtx.ClusterID != "prod" || gotCtx.Region != "us-east-1" {
		t.Errorf("cluster context = %+v, want clusterID=prod region=us-east-1", gotCtx)
	}
	if gotCtx.RootCA != "Y2E=" {
		t.Errorf("RootCA = %q, want the evaluate certificateData", gotCtx.RootCA)
	}
}

func TestExecCredentialFallsBackToEvaluateRole(t *testing.T) {
	var gotRole string
	svc := NewServiceWithBackend(evaluateBackend(ConnectionDirect, "Y2E="))
	svc.SetCredentialFlow(&stubFlow{
		directFn: func(_ *ElevateResult, cctx *sdkk8s.IdsecSCAK8sClusterContext, _ bool) (*k8smodels.IdsecSCAK8sExecCredential, error) {
			gotRole = cctx.RoleID
			return &k8smodels.IdsecSCAK8sExecCredential{}, nil
		},
	})

	if _, err := svc.ExecCredential(t.Context(), ExecCredentialParams{CSP: "aws", FQDN: "host"}); err != nil {
		t.Fatalf("ExecCredential: %v", err)
	}
	if gotRole != "role-from-evaluate" {
		t.Errorf("RoleID = %q, want the role from evaluate when --role-id is omitted", gotRole)
	}
}

func TestExecCredentialProxyFlow(t *testing.T) {
	var proxyCSP string
	var proxyCtx *sdkk8s.IdsecSCAK8sClusterContext

	backend := evaluateBackend(ConnectionProxy, "Y2E=")
	backend.proxyFn = func(csp string, cctx *sdkk8s.IdsecSCAK8sClusterContext) (*k8smodels.IdsecSCAK8sExecCredential, error) {
		proxyCSP, proxyCtx = csp, cctx
		return &k8smodels.IdsecSCAK8sExecCredential{
			Status: k8smodels.IdsecSCAK8sExecCredentialStatus{ClientCertificateData: "cert", ClientKeyData: "key"},
		}, nil
	}

	svc := NewServiceWithBackend(backend)
	svc.SetCredentialFlow(&stubFlow{
		proxyFn: func(*ElevateResult, *sdkk8s.IdsecSCAK8sClusterContext, bool) (string, error) {
			return "k8s-token", nil
		},
		directFn: func(*ElevateResult, *sdkk8s.IdsecSCAK8sClusterContext, bool) (*k8smodels.IdsecSCAK8sExecCredential, error) {
			t.Error("Direct must not be called for a proxy cluster")
			return nil, nil
		},
	})

	cred, err := svc.ExecCredential(t.Context(), ExecCredentialParams{CSP: "aws", FQDN: "host"})
	if err != nil {
		t.Fatalf("ExecCredential: %v", err)
	}
	if cred.Status.ClientCertificateData != "cert" {
		t.Errorf("cred = %+v", cred.Status)
	}
	if proxyCSP != "AWS" {
		t.Errorf("proxy csp = %q", proxyCSP)
	}
	if proxyCtx.K8sToken != "k8s-token" {
		t.Errorf("K8sToken = %q, want it set from the proxy token flow", proxyCtx.K8sToken)
	}
}

func TestExecCredentialProxyRequiresCertificateData(t *testing.T) {
	svc := NewServiceWithBackend(evaluateBackend(ConnectionProxy, ""))
	svc.SetCredentialFlow(&stubFlow{
		proxyFn: func(*ElevateResult, *sdkk8s.IdsecSCAK8sClusterContext, bool) (string, error) {
			return "k8s-token", nil
		},
	})

	_, err := svc.ExecCredential(t.Context(), ExecCredentialParams{CSP: "aws", FQDN: "host"})
	if err == nil || !strings.Contains(err.Error(), "certificate data") {
		t.Fatalf("err = %v, want a missing-certificate-data error", err)
	}
}

func TestExecCredentialPropagatesInteractiveFlag(t *testing.T) {
	for _, interactive := range []bool{true, false} {
		var got bool
		svc := NewServiceWithBackend(evaluateBackend(ConnectionDirect, "Y2E="))
		svc.SetCredentialFlow(&stubFlow{
			directFn: func(_ *ElevateResult, _ *sdkk8s.IdsecSCAK8sClusterContext, i bool) (*k8smodels.IdsecSCAK8sExecCredential, error) {
				got = i
				return &k8smodels.IdsecSCAK8sExecCredential{}, nil
			},
		})

		if _, err := svc.ExecCredential(t.Context(), ExecCredentialParams{
			CSP: "aws", FQDN: "host", Interactive: interactive,
		}); err != nil {
			t.Fatalf("ExecCredential: %v", err)
		}
		if got != interactive {
			t.Errorf("interactive = %v, want %v", got, interactive)
		}
	}
}

func TestExecCredentialSurfacesInteractionRequired(t *testing.T) {
	svc := NewServiceWithBackend(evaluateBackend(ConnectionDirect, "Y2E="))
	svc.SetCredentialFlow(&stubFlow{
		directFn: func(*ElevateResult, *sdkk8s.IdsecSCAK8sClusterContext, bool) (*k8smodels.IdsecSCAK8sExecCredential, error) {
			return nil, ErrInteractionRequired
		},
	})

	_, err := svc.ExecCredential(t.Context(), ExecCredentialParams{CSP: "aws", FQDN: "host"})
	if !errors.Is(err, ErrInteractionRequired) {
		t.Fatalf("err = %v, want ErrInteractionRequired", err)
	}
}

func TestExecCredentialValidatesCSP(t *testing.T) {
	svc := NewServiceWithBackend(evaluateBackend(ConnectionDirect, ""))
	if _, err := svc.ExecCredential(t.Context(), ExecCredentialParams{CSP: "gcp", FQDN: "host"}); err == nil {
		t.Fatal("expected an unsupported-CSP error")
	}
}
