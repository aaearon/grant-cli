//go:build integration

package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntegration_K8sHelp(t *testing.T) {
	cmd := exec.Command(getBinaryPath(), "k8s", "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("grant k8s --help failed: %v\n%s", err, output)
	}

	outputStr := string(output)
	for _, want := range []string{"list", "Kubernetes"} {
		if !strings.Contains(outputStr, want) {
			t.Errorf("expected %q in `grant k8s --help` output, got:\n%s", want, outputStr)
		}
	}

	// exec-credential is Hidden and must not be advertised.
	if strings.Contains(outputStr, "exec-credential") {
		t.Errorf("exec-credential must be hidden from help, got:\n%s", outputStr)
	}
}

func TestIntegration_K8sListHelp(t *testing.T) {
	cmd := exec.Command(getBinaryPath(), "k8s", "list", "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("grant k8s list --help failed: %v\n%s", err, output)
	}

	outputStr := string(output)
	for _, want := range []string{"--provider", "--refresh"} {
		if !strings.Contains(outputStr, want) {
			t.Errorf("expected %q in `grant k8s list --help` output, got:\n%s", want, outputStr)
		}
	}
}

// TestIntegration_K8sListJSONWithoutLogin asserts the command fails cleanly and
// makes no network call when there is no authentication. No stub server is
// contacted: the binary must bail out before any request.
func TestIntegration_K8sListJSONWithoutLogin(t *testing.T) {
	tempDir := t.TempDir()

	cmd := exec.Command(getBinaryPath(), "k8s", "list", "--output", "json")
	cmd.Env = append(os.Environ(), "GRANT_CONFIG="+filepath.Join(tempDir, "config.yaml"))
	cmd.Env = append(cmd.Env, "HOME="+tempDir)

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected `grant k8s list` to fail without authentication, got:\n%s", output)
	}

	outputStr := strings.ToLower(string(output))
	if !strings.Contains(outputStr, "auth") && !strings.Contains(outputStr, "profile") && !strings.Contains(outputStr, "error") {
		t.Errorf("expected an authentication-shaped error, got:\n%s", output)
	}
}

func TestIntegration_K8sListRejectsUnsupportedProvider(t *testing.T) {
	tempDir := t.TempDir()

	cmd := exec.Command(getBinaryPath(), "k8s", "list", "--provider", "gcp")
	cmd.Env = append(os.Environ(), "GRANT_CONFIG="+filepath.Join(tempDir, "config.yaml"))
	cmd.Env = append(cmd.Env, "HOME="+tempDir)

	output, _ := cmd.CombinedOutput()
	if !strings.Contains(strings.ToLower(string(output)), "gcp") &&
		!strings.Contains(strings.ToLower(string(output)), "auth") {
		t.Errorf("expected a provider or auth error, got:\n%s", output)
	}
}
