// Package k8s wraps the SDK's SCA Kubernetes service with grant-shaped models,
// context propagation and errors.
//
// The SDK package github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s owns
// all transport and credential flows (X-CLI-Signature, DPA SSO acquire, STS
// presign, Azure CLI token acquisition, JWE decryption). grant owns the command,
// selector, cache and kubeconfig-file layers on top of it.
//
// Context propagation: only GenerateKubeconfigParallel accepts a context.Context.
// Every other SDK entry point uses context.Background() internally, so grant
// enforces cancellation at this wrapper boundary via runWithContext. That aborts
// the caller promptly but cannot cancel the in-flight HTTP request; the goroutine
// runs to completion and its result is discarded.
package k8s

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	sdkk8s "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// Connection method values returned by the evaluate endpoint.
const (
	ConnectionDirect = "direct"
	ConnectionProxy  = "proxy"
)

// SupportedCSPs lists the cloud providers SCA supports for Kubernetes clusters.
// GCP is deliberately absent: the SCA k8s API does not support it.
var SupportedCSPs = []string{"aws", "azure"}

// ErrUnsupportedCSP is returned when a provider outside SupportedCSPs is requested.
var ErrUnsupportedCSP = errors.New("unsupported cloud provider for Kubernetes")

// Cluster is grant's view of a single SCA-eligible Kubernetes cluster.
type Cluster struct {
	Provider       string `json:"provider"`
	Name           string `json:"name"`
	ClusterID      string `json:"clusterId"`
	FQDN           string `json:"fqdn,omitempty"`
	Region         string `json:"region,omitempty"`
	Scope          string `json:"scope,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	WorkspaceID    string `json:"workspaceId,omitempty"`
	WorkspaceName  string `json:"workspaceName,omitempty"`
	WorkspaceType  string `json:"workspaceType,omitempty"`
	RoleName       string `json:"role,omitempty"`
	RoleID         string `json:"roleId,omitempty"`
	OrganizationID string `json:"organizationId,omitempty"`
}

// Connection is the evaluate result for a single cluster.
type Connection struct {
	ConnectionMethod string
	CertificateData  string
	ClusterID        string
	Region           string
	RoleID           string
	WorkspaceID      string
	OrganizationID   string
	Namespace        string
}

// ElevateParams are the inputs for a cluster elevation.
type ElevateParams struct {
	CSP            string
	FQDN           string
	RoleID         string
	OrganizationID string
	Namespace      string
}

// ElevateResult is grant's view of a single elevate result.
type ElevateResult struct {
	SessionID      string
	SessionExpTime string
	RoleName       string
	RoleID         string
	TargetID       string
	WorkspaceID    string
	CSP            string

	// SDK is the raw SDK result, needed by the SDK token providers.
	SDK *k8smodels.IdsecSCAK8sElevateResult
}

// KubeconfigFailure records a per-CSP kubeconfig generation failure.
type KubeconfigFailure struct {
	CSP   string `json:"csp"`
	Error string `json:"error"`
}

// backend is the seam over the SDK service, so tests never touch the network.
type backend interface {
	ListTargets(req *k8smodels.IdsecSCAk8sListClustersRequest) (*k8smodels.IdsecSCAk8sListClustersResponse, error)
	EvaluateEligibility(req *k8smodels.IdsecSCAK8sEvaluateRequest, csp string) (*k8smodels.IdsecSCAK8sEvaluateResponse, error)
	Elevate(req *k8smodels.IdsecSCAK8sElevateKubectlRequest) (*k8smodels.IdsecSCAK8sElevateResponse, error)
	GenerateKubeconfigParallel(ctx context.Context, csps []string, kubeconfigLocation string) *k8smodels.IdsecSCAK8sGenerateKubeconfigParallelResponse
	GenerateProxyExecCredential(csp string, cctx *sdkk8s.IdsecSCAK8sClusterContext) (*k8smodels.IdsecSCAK8sExecCredential, error)
}

// Service is grant's wrapper around the SDK SCA K8s service.
type Service struct {
	backend backend
}

// NewService creates a Service backed by the real SDK k8s service.
func NewService(authenticators ...auth.IdsecAuth) (*Service, error) {
	sdkSvc, err := sdkk8s.NewIdsecSCAK8sService(authenticators...)
	if err != nil {
		return nil, fmt.Errorf("failed to create SCA k8s service: %w", err)
	}
	return &Service{backend: sdkSvc}, nil
}

// NewServiceWithBackend creates a Service over an injected backend. For tests.
func NewServiceWithBackend(b backend) *Service {
	return &Service{backend: b}
}

// NormalizeCSP validates and upper-cases a provider name for the SCA k8s API.
func NormalizeCSP(csp string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(csp))
	for _, supported := range SupportedCSPs {
		if trimmed == supported {
			return strings.ToUpper(trimmed), nil
		}
	}
	return "", fmt.Errorf("%w: %q (supported: %s)", ErrUnsupportedCSP, csp, strings.Join(SupportedCSPs, ", "))
}

// runWithContext runs fn on a goroutine and returns as soon as either fn
// completes or ctx is done. The SDK call itself is not cancellable, so on
// cancellation the goroutine keeps running and its result is dropped.
func runWithContext[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	type outcome struct {
		val T
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		val, err := fn()
		done <- outcome{val: val, err: err}
	}()

	select {
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	case res := <-done:
		return res.val, res.err
	}
}

// ListClusters lists SCA-eligible clusters. An empty csp lists every supported
// provider; results are merged into a single flat slice.
func (s *Service) ListClusters(ctx context.Context, csp string) ([]Cluster, error) {
	req := &k8smodels.IdsecSCAk8sListClustersRequest{}
	if strings.TrimSpace(csp) == "" {
		req.All = true
	} else {
		normalized, err := NormalizeCSP(csp)
		if err != nil {
			return nil, err
		}
		req.CSP = normalized
	}

	resp, err := runWithContext(ctx, func() (*k8smodels.IdsecSCAk8sListClustersResponse, error) {
		return s.backend.ListTargets(req)
	})
	if err != nil {
		return nil, fmt.Errorf("list clusters failed: %w", err)
	}
	if resp == nil {
		return nil, nil
	}

	clusters := make([]Cluster, 0, resp.Total)
	if len(resp.Responses) > 0 {
		for _, provider := range SupportedCSPs {
			perCSP, ok := resp.Responses[provider]
			if !ok {
				continue
			}
			clusters = append(clusters, convertTargets(provider, perCSP.Response)...)
		}
		return clusters, nil
	}

	return append(clusters, convertTargets(strings.ToLower(req.CSP), resp.Response)...), nil
}

func convertTargets(provider string, targets []k8smodels.IdsecSCAk8sListClustersEligibleTarget) []Cluster {
	out := make([]Cluster, 0, len(targets))
	for _, t := range targets {
		c := Cluster{
			Provider:      provider,
			ClusterID:     t.Target.ClusterID,
			Region:        t.Target.Region,
			Scope:         t.Target.Scope,
			WorkspaceID:   t.WorkspaceID,
			WorkspaceName: t.WorkspaceName,
			WorkspaceType: t.WorkspaceType,
			RoleName:      t.Role.Name,
			RoleID:        t.Role.ID,
		}
		if t.Target.FQDN != nil {
			c.FQDN = *t.Target.FQDN
		}
		if t.Target.NamespaceID != nil {
			c.Namespace = sdkk8s.ParseNamespaceName(*t.Target.NamespaceID)
		}
		if t.OrganizationID != nil {
			c.OrganizationID = *t.OrganizationID
		}
		c.Name = clusterDisplayName(c.ClusterID, c.FQDN)
		out = append(out, c)
	}
	return out
}

// clusterDisplayName derives a short cluster name from an EKS ARN or an Azure
// resource ID, falling back to the raw ID and then the FQDN.
func clusterDisplayName(clusterID, fqdn string) string {
	id := strings.TrimSpace(clusterID)
	if id == "" {
		return fqdn
	}
	if idx := strings.LastIndex(id, "/"); idx >= 0 && idx < len(id)-1 {
		return id[idx+1:]
	}
	return id
}

// Evaluate resolves the connection method (direct or proxy) for a cluster FQDN.
func (s *Service) Evaluate(ctx context.Context, csp, fqdn string) (*Connection, error) {
	normalized, err := NormalizeCSP(csp)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(fqdn) == "" {
		return nil, errors.New("cluster FQDN is required to evaluate eligibility")
	}

	req := &k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{{FQDN: fqdn}},
	}

	resp, err := runWithContext(ctx, func() (*k8smodels.IdsecSCAK8sEvaluateResponse, error) {
		return s.backend.EvaluateEligibility(req, normalized)
	})
	if err != nil {
		return nil, fmt.Errorf("evaluate cluster eligibility failed: %w", err)
	}
	if resp == nil || len(resp.Response) == 0 {
		return nil, fmt.Errorf("cluster %q is not eligible for %s, run 'grant k8s list' to see eligible clusters", fqdn, strings.ToLower(normalized))
	}

	r := resp.Response[0]
	conn := &Connection{
		ConnectionMethod: strings.ToLower(strings.TrimSpace(r.ConnectionMethod)),
		CertificateData:  r.CertificateData,
		ClusterID:        r.Target.ClusterID,
		Region:           r.Target.Region,
		RoleID:           r.Role.ID,
		WorkspaceID:      r.WorkspaceID,
	}
	if r.OrganizationID != nil {
		conn.OrganizationID = *r.OrganizationID
	}
	if r.Target.NamespaceID != nil {
		conn.Namespace = sdkk8s.ParseNamespaceName(*r.Target.NamespaceID)
	}
	return conn, nil
}

// Elevate performs a JIT elevation for a single cluster.
func (s *Service) Elevate(ctx context.Context, p ElevateParams) (*ElevateResult, error) {
	normalized, err := NormalizeCSP(p.CSP)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(p.FQDN) == "" {
		return nil, errors.New("cluster FQDN is required to elevate")
	}
	if strings.TrimSpace(p.RoleID) == "" {
		return nil, errors.New("role ID is required to elevate")
	}

	req := &k8smodels.IdsecSCAK8sElevateKubectlRequest{
		CSP:            normalized,
		FQDN:           p.FQDN,
		RoleID:         p.RoleID,
		OrganizationID: p.OrganizationID,
		Namespace:      p.Namespace,
	}

	resp, err := runWithContext(ctx, func() (*k8smodels.IdsecSCAK8sElevateResponse, error) {
		return s.backend.Elevate(req)
	})
	if err != nil {
		return nil, fmt.Errorf("cluster elevation failed: %w", err)
	}
	if resp == nil || len(resp.Response.Results) == 0 {
		return nil, errors.New("cluster elevation returned no results")
	}

	r := resp.Response.Results[0]
	return &ElevateResult{
		SessionID:      r.SessionID,
		SessionExpTime: r.SessionExpTime,
		RoleName:       r.RoleName,
		RoleID:         r.RoleID,
		TargetID:       r.TargetID,
		WorkspaceID:    r.WorkspaceID,
		CSP:            resp.Response.CSP,
		SDK:            &r,
	}, nil
}

// GenerateKubeconfigs fetches DPA-generated kubeconfigs for the given providers.
// This is the single SDK entry point that accepts a context, so the caller's
// context is propagated directly.
func (s *Service) GenerateKubeconfigs(ctx context.Context, csps []string) (map[string]string, []KubeconfigFailure, error) {
	if len(csps) == 0 {
		return nil, nil, errors.New("at least one cloud provider is required to generate a kubeconfig")
	}

	normalized := make([]string, 0, len(csps))
	for _, csp := range csps {
		n, err := NormalizeCSP(csp)
		if err != nil {
			return nil, nil, err
		}
		normalized = append(normalized, strings.ToLower(n))
	}

	resp := s.backend.GenerateKubeconfigParallel(ctx, normalized, "")
	if resp == nil {
		return nil, nil, errors.New("kubeconfig generation returned no response")
	}

	succeeded := make(map[string]string, len(resp.Succeeded))
	for _, outcome := range resp.Succeeded {
		succeeded[strings.ToLower(outcome.CSP)] = outcome.Kubeconfig
	}

	failures := make([]KubeconfigFailure, 0, len(resp.Failed))
	for _, outcome := range resp.Failed {
		failures = append(failures, KubeconfigFailure{CSP: strings.ToLower(outcome.CSP), Error: outcome.Error})
	}

	return succeeded, failures, nil
}

// ProxyExecCredential asks the SDK for a proxy-method ExecCredential. The SDK
// bakes its early-refresh buffer into status.expirationTimestamp; grant never
// re-applies it.
func (s *Service) ProxyExecCredential(ctx context.Context, csp string, cctx *sdkk8s.IdsecSCAK8sClusterContext) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	normalized, err := NormalizeCSP(csp)
	if err != nil {
		return nil, err
	}
	cred, err := runWithContext(ctx, func() (*k8smodels.IdsecSCAK8sExecCredential, error) {
		return s.backend.GenerateProxyExecCredential(normalized, cctx)
	})
	if err != nil {
		return nil, fmt.Errorf("proxy credential generation failed: %w", err)
	}
	return cred, nil
}
