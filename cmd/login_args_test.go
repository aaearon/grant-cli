package cmd

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	"github.com/mattn/go-isatty"
)

// TestRunLogin_AutoConfiguresMissingProfile kills REQ-20: disabling the
// `if profile == nil` branch at cmd/login.go:52 would authenticate against a
// nil profile instead of running the configure flow. The feature IS
// implemented — login_test.go previously skipped this with the factually wrong
// reason "Auto-configure not yet implemented".
//
// The configure flow prompts through survey on a non-terminal stdin, which
// fails rather than blocking; the assertion is on the announcement plus the
// fact that authentication was never attempted.
func TestRunLogin_AutoConfiguresMissingProfile(t *testing.T) {
	// runConfigure prompts through survey, which reads os.Stdin directly and
	// has no injectable seam. On a real terminal that would block forever, so
	// skip rather than hang; CI and every non-interactive run still cover it.
	if isatty.IsTerminal(os.Stdin.Fd()) {
		t.Skip("stdin is a terminal: the configure prompt would block on real input")
	}

	// An empty profiles folder: LoadProfile("grant") finds nothing.
	t.Setenv("IDSEC_PROFILES_FOLDER", t.TempDir())

	auth := &mockAuthenticator{
		authenticateFunc: func(*models.IdsecProfile, *authmodels.IdsecAuthProfile, *authmodels.IdsecSecret, bool, bool) (*authmodels.IdsecToken, error) {
			t.Error("authentication must not be attempted before the profile is configured")
			return nil, errors.New("unreachable")
		},
	}

	cmd := NewLoginCommandWithAuth(auth)
	output, err := executeCommand(cmd)

	if !strings.Contains(output, "No configuration found") {
		t.Errorf("expected the auto-configure announcement, got:\n%s", output)
	}
	if err == nil {
		t.Error("expected configuration to fail without a terminal, got nil")
	}
}

// TestRunLogin_AuthenticateFlags kills REQ-21: swapping the force/refreshAuth
// arguments at cmd/login.go:74. `grant login` must force a fresh
// authentication (refreshAuth=true) without forcing a profile rewrite
// (force=false); the swap silently reuses a cached token.
func TestRunLogin_AuthenticateFlags(t *testing.T) {
	t.Setenv("IDSEC_PROFILES_FOLDER", t.TempDir())

	profile := &models.IdsecProfile{
		ProfileName: "grant",
		AuthProfiles: map[string]*authmodels.IdsecAuthProfile{
			"isp": {
				Username:   "test.user@example.com",
				AuthMethod: authmodels.Identity,
				AuthMethodSettings: &authmodels.IdentityIdsecAuthMethodSettings{
					IdentityURL:            "https://example.cyberark.cloud",
					IdentityMFAInteractive: true,
				},
			},
		},
	}
	loader := &profiles.FileSystemProfilesLoader{}
	if err := loader.SaveProfile(profile); err != nil {
		t.Fatalf("failed to create test profile: %v", err)
	}

	var gotForce, gotRefresh bool
	var gotSecret *authmodels.IdsecSecret
	var calls int
	auth := &mockAuthenticator{
		authenticateFunc: func(_ *models.IdsecProfile, _ *authmodels.IdsecAuthProfile, secret *authmodels.IdsecSecret, force, refreshAuth bool) (*authmodels.IdsecToken, error) {
			calls++
			gotForce, gotRefresh, gotSecret = force, refreshAuth, secret
			return &authmodels.IdsecToken{Token: "jwt", Username: "test.user@example.com"}, nil
		},
	}

	cmd := NewLoginCommandWithAuth(auth)
	if _, err := executeCommand(cmd); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if calls != 1 {
		t.Fatalf("expected exactly 1 Authenticate call, got %d", calls)
	}
	if gotForce {
		t.Error("force = true, want false")
	}
	if !gotRefresh {
		t.Error("refreshAuth = false, want true")
	}
	if gotSecret == nil || gotSecret.Secret != "" {
		t.Errorf("secret = %+v, want an empty interactive secret", gotSecret)
	}
}
