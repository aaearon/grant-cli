package k8s

import (
	"context"
	"errors"
	"fmt"
	"strings"

	sdkk8s "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// ErrInteractionRequired is returned when a credential flow needs a browser or
// an interactive login but kubectl told us stdin is unavailable.
var ErrInteractionRequired = errors.New("interactive authentication required")

// ExecCredential is the kubectl exec-credential plugin payload. Aliased from the
// SDK so command signatures do not leak SDK type names.
type ExecCredential = k8smodels.IdsecSCAK8sExecCredential

// ExecCredentialStatus is the status block of an ExecCredential.
type ExecCredentialStatus = k8smodels.IdsecSCAK8sExecCredentialStatus

// ExecCredentialParams are the inputs for a kubectl exec-credential request.
type ExecCredentialParams struct {
	CSP            string
	FQDN           string
	RoleID         string
	OrganizationID string
	Namespace      string

	// ElevateToken is the ISP session JWT. The Azure provider decodes it to check
	// the az CLI session belongs to the same identity.
	ElevateToken string

	// Interactive reports whether kubectl said stdin is available. When false,
	// flows that would open a browser or run `az login` fail fast instead.
	Interactive bool

	// Diagnostics enables the SDK's kubectl-login stderr diagnostics.
	Diagnostics bool
}

// credentialFlow is the seam over the SDK's CSP-specific credential providers,
// which reach out to AWS STS / SSO OIDC and the Azure CLI. Tests inject a stub.
type credentialFlow interface {
	Direct(res *ElevateResult, cctx *sdkk8s.IdsecSCAK8sClusterContext, interactive bool) (*k8smodels.IdsecSCAK8sExecCredential, error)
	ProxyToken(res *ElevateResult, cctx *sdkk8s.IdsecSCAK8sClusterContext, interactive bool) (string, error)
}

// ExecCredential runs the full evaluate → elevate → credential flow for one
// cluster and returns the kubectl ExecCredential.
//
// The returned status.expirationTimestamp already has the SDK's early-refresh
// buffer subtracted; callers must not apply another one.
func (s *Service) ExecCredential(ctx context.Context, p ExecCredentialParams) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	csp, err := NormalizeCSP(p.CSP)
	if err != nil {
		return nil, err
	}

	conn, err := s.Evaluate(ctx, csp, p.FQDN)
	if err != nil {
		return nil, err
	}

	roleID := p.RoleID
	if strings.TrimSpace(roleID) == "" {
		roleID = conn.RoleID
	}
	orgID := p.OrganizationID
	if strings.TrimSpace(orgID) == "" {
		orgID = conn.OrganizationID
	}

	res, err := s.Elevate(ctx, ElevateParams{
		CSP:            csp,
		FQDN:           p.FQDN,
		RoleID:         roleID,
		OrganizationID: orgID,
		Namespace:      p.Namespace,
	})
	if err != nil {
		return nil, err
	}

	cctx := buildClusterContext(csp, roleID, orgID, p, conn, res)

	if conn.ConnectionMethod == ConnectionProxy {
		return s.proxyCredential(ctx, csp, cctx, res, p.Interactive)
	}
	return s.flow().Direct(res, cctx, p.Interactive)
}

func (s *Service) proxyCredential(
	ctx context.Context,
	csp string,
	cctx *sdkk8s.IdsecSCAK8sClusterContext,
	res *ElevateResult,
	interactive bool,
) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	token, err := s.flow().ProxyToken(res, cctx, interactive)
	if err != nil {
		return nil, err
	}
	cctx.K8sToken = token
	if token != "" && cctx.RootCA == "" {
		return nil, errors.New("proxy connection requires the cluster certificate data, which the evaluate API did not return")
	}
	return s.ProxyExecCredential(ctx, csp, cctx)
}

func buildClusterContext(
	csp, roleID, orgID string,
	p ExecCredentialParams,
	conn *Connection,
	res *ElevateResult,
) *sdkk8s.IdsecSCAK8sClusterContext {
	clusterID := conn.ClusterID
	region := conn.Region
	if csp == "AWS" {
		if r, name, err := sdkk8s.ParseEKSARN(res.TargetID); err == nil {
			region, clusterID = r, name
		}
	}

	return &sdkk8s.IdsecSCAK8sClusterContext{
		CSP:            csp,
		ClusterID:      clusterID,
		RoleID:         roleID,
		Region:         region,
		FQDN:           p.FQDN,
		OrganizationID: orgID,
		Namespace:      p.Namespace,
		ElevateToken:   p.ElevateToken,
		RootCA:         conn.CertificateData,
		Diagnostics:    p.Diagnostics,
	}
}

func (s *Service) flow() credentialFlow {
	if s.credFlow != nil {
		return s.credFlow
	}
	return sdkCredentialFlow{}
}

// sdkCredentialFlow delegates to the SDK's per-CSP providers.
type sdkCredentialFlow struct{}

// Direct produces an ExecCredential for the direct connection method.
func (sdkCredentialFlow) Direct(
	res *ElevateResult,
	cctx *sdkk8s.IdsecSCAK8sClusterContext,
	interactive bool,
) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	switch cctx.CSP {
	case "AZURE":
		return azureCredential(cctx, interactive)
	case "AWS":
		if err := hydrateAWSIDC(res, cctx, interactive); err != nil {
			return nil, err
		}
	}

	provider, err := sdkk8s.GetTokenProvider(cctx.CSP)
	if err != nil {
		return nil, err
	}
	cred, err := provider.GenerateToken(res.SDK, cctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cluster credential: %w", err)
	}
	return cred, nil
}

// ProxyToken returns the cluster API token that must be JWE-wrapped for the DPA
// proxy. AWS IAM-role clusters need none.
func (f sdkCredentialFlow) ProxyToken(
	res *ElevateResult,
	cctx *sdkk8s.IdsecSCAK8sClusterContext,
	interactive bool,
) (string, error) {
	switch cctx.CSP {
	case "AZURE":
		return azureAccessToken(cctx, interactive)
	case "AWS":
		if !sdkk8s.IsAWSIDCPermissionSetRole(cctx.RoleID) {
			return "", nil
		}
		cred, err := f.Direct(res, cctx, interactive)
		if err != nil {
			return "", err
		}
		return cred.Status.Token, nil
	}
	return "", nil
}

func hydrateAWSIDC(res *ElevateResult, cctx *sdkk8s.IdsecSCAK8sClusterContext, interactive bool) error {
	if !sdkk8s.NeedsAWSIDCDeviceRegistration(res.SDK) {
		return nil
	}
	if !interactive {
		return fmt.Errorf(
			"%w: this AWS Identity Center role needs a browser-based device login, but kubectl reported that stdin is unavailable; run 'grant k8s elevate %s' in a terminal first",
			ErrInteractionRequired, cctx.FQDN)
	}
	if err := sdkk8s.HydrateAWSAccessCredentialsFromElevate(res.SDK, cctx.Diagnostics, nil); err != nil {
		return fmt.Errorf("AWS Identity Center device registration failed: %w", err)
	}
	return nil
}

func azureCredential(cctx *sdkk8s.IdsecSCAK8sClusterContext, interactive bool) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	token, err := azureAccessToken(cctx, interactive)
	if err != nil {
		return nil, err
	}
	return sdkk8s.BuildAzureExecCredential(token), nil
}

// azureAccessToken acquires an AKS token through the Azure CLI. The Azure path
// requires the Azure CLI to be installed and logged in; when kubectl says stdin
// is unavailable we only verify an existing session rather than running
// `az login`.
func azureAccessToken(cctx *sdkk8s.IdsecSCAK8sClusterContext, interactive bool) (string, error) {
	if !interactive {
		token, err := sdkk8s.VerifyAzureCLISession(cctx.OrganizationID, cctx.ElevateToken)
		if err != nil {
			return "", fmt.Errorf(
				"%w: no usable Azure CLI session and kubectl reported that stdin is unavailable; run 'az login' in a terminal first: %w",
				ErrInteractionRequired, err)
		}
		return token, nil
	}

	token, err := sdkk8s.EnsureAzureCLISession(cctx.OrganizationID, cctx.ElevateToken, azureSubscription(cctx), cctx.Diagnostics)
	if err != nil {
		return "", fmt.Errorf("Azure CLI authentication failed (the Azure path requires the Azure CLI installed and logged in): %w", err)
	}
	return token, nil
}

func azureSubscription(cctx *sdkk8s.IdsecSCAK8sClusterContext) string {
	return sdkk8s.AzureSubscriptionFromTargetID(cctx.ClusterID)
}
