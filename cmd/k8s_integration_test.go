//go:build integration

package cmd

import (
	"strings"
	"testing"
)

// authFailure is the exact error the SDK authenticator emits against the empty
// sandbox profile directory, before any network call is made.
const authFailure = "authentication failed: either a profile or a specific auth profile must be supplied"

func TestIntegration_K8sHelp(t *testing.T) {
	got := runGrant(t, isolatedEnv(t), "k8s", "--help")

	if got.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", got.exitCode, got.output)
	}
	for _, want := range []string{"list", "elevate", "kubeconfig", "Kubernetes"} {
		if !got.contains(want) {
			t.Errorf("output missing %q, got:\n%s", want, got.output)
		}
	}
	// exec-credential is Hidden and must not be advertised.
	if got.contains("exec-credential") {
		t.Errorf("exec-credential must be hidden from help, got:\n%s", got.output)
	}
}

func TestIntegration_K8sListHelp(t *testing.T) {
	got := runGrant(t, isolatedEnv(t), "k8s", "list", "--help")

	if got.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", got.exitCode, got.output)
	}
	for _, want := range []string{"--provider", "--refresh"} {
		if !got.contains(want) {
			t.Errorf("output missing %q, got:\n%s", want, got.output)
		}
	}
}

// TestIntegration_K8sListJSONWithoutLogin asserts the command fails cleanly and
// makes no network call when there is no authentication. No stub server is
// contacted: the binary must bail out before any request.
func TestIntegration_K8sListJSONWithoutLogin(t *testing.T) {
	got := runGrant(t, isolatedEnv(t), "k8s", "list", "--output", "json")

	if got.exitCode != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", got.exitCode, got.output)
	}
	for _, want := range []string{authFailure, "Hint: re-run with --verbose for more details"} {
		if !got.contains(want) {
			t.Errorf("output missing %q, got:\n%s", want, got.output)
		}
	}
	// --output json must not emit a partial document alongside the failure.
	if strings.Contains(got.output, "{") {
		t.Errorf("k8s list printed JSON despite failing to authenticate:\n%s", got.output)
	}
}

// TestIntegration_K8sListUnsupportedProviderStillRequiresAuth pins the current
// ordering: `k8s list` authenticates before it validates --provider, so an
// unsupported provider surfaces the authentication error, not a provider one.
// The assertion is deliberately exact — the previous version accepted "gcp" OR
// "auth" and so passed without ever proving which error the user actually sees.
func TestIntegration_K8sListUnsupportedProviderStillRequiresAuth(t *testing.T) {
	got := runGrant(t, isolatedEnv(t), "k8s", "list", "--provider", "gcp")

	if got.exitCode != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", got.exitCode, got.output)
	}
	if !got.contains(authFailure) {
		t.Errorf("output missing %q, got:\n%s", authFailure, got.output)
	}
}
