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
	// KNOWN COVERAGE GAP (ledger COV-02). Under a PTY this test does not run at
	// all, so the auto-configure branch has ZERO coverage there and REQ-20 is
	// unpinned for anyone running `go test` from a terminal that hands the
	// process a real stdin.
	//
	// There is no seam to close it with: runConfigure prompts through survey,
	// which reads os.Stdin directly and offers no injection point, so on a real
	// terminal this would block on input forever rather than fail. Skipping is
	// the lesser evil. `go test`, CI and every non-interactive run get a
	// non-TTY stdin and do exercise the branch — which is why this is accepted
	// rather than fixed. Closing it properly means giving runConfigure a stdin
	// seam first.
	if isatty.IsTerminal(os.Stdin.Fd()) {
		t.Skip("stdin is a terminal: the configure prompt would block on real input")
	}

	// survey renders the configure prompt to os.Stdout directly, not to the
	// cobra buffer, so without this the escape sequences (including ESC[6n,
	// which the terminal answers on stdin) land on the developer's console.
	withDiscardedStdout(t)

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
