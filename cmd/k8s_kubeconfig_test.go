package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/k8s"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const generatedAWSKubeconfig = `apiVersion: v1
kind: Config
clusters:
  - name: eks-prod
    cluster:
      server: https://prod.eks.example
users:
  - name: eks-prod-user
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: idsec
        args: ["sca", "k8s", "kubectl-login", "--csp", "aws", "--fqdn", "prod.eks.example"]
contexts:
  - name: eks-prod
    context:
      cluster: eks-prod
      user: eks-prod-user
`

const preExistingKubeconfig = `apiVersion: v1
kind: Config
current-context: work
clusters:
  - name: work
    cluster:
      server: https://work.example
users:
  - name: work-user
    user:
      token: mytoken
contexts:
  - name: work
    context:
      cluster: work
      user: work-user
`

// mockKubeconfigGenerator implements kubeconfigGenerator.
type mockKubeconfigGenerator struct {
	configs  map[string]string
	failures []k8s.KubeconfigFailure
	err      error
	gotCSPs  []string
}

func (m *mockKubeconfigGenerator) GenerateKubeconfigs(_ context.Context, csps []string) (map[string]string, []k8s.KubeconfigFailure, error) {
	m.gotCSPs = csps
	return m.configs, m.failures, m.err
}

func pinGrantPath(t *testing.T, path string) {
	t.Helper()
	setOutputFormat(t, "text")
	original := grantExecutablePath
	t.Cleanup(func() { grantExecutablePath = original })
	grantExecutablePath = func() (string, error) { return path, nil }
}

func runKubeconfig(t *testing.T, cmd *cobra.Command, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errBuf.String(), err
}

func awsGenerator() *mockKubeconfigGenerator {
	return &mockKubeconfigGenerator{configs: map[string]string{"aws": generatedAWSKubeconfig}}
}

func TestKubeconfigMergesIntoExistingFile(t *testing.T) {
	pinGrantPath(t, "/usr/local/bin/grant")

	dir := t.TempDir()
	target := filepath.Join(dir, "config")
	if err := os.WriteFile(target, []byte(preExistingKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewK8sKubeconfigCommandWithDeps(&mockAuthLoader{}, awsGenerator())
	stdout, _, err := runKubeconfig(t, cmd, "--file", target)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(stdout, target) {
		t.Errorf("output should name the target file: %q", stdout)
	}

	data, err := os.ReadFile(target) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("result is not valid YAML: %v\n%s", err, data)
	}

	// The user's own entries survive and current-context is untouched.
	if cfg["current-context"] != "work" {
		t.Errorf("current-context = %v, want it left at work", cfg["current-context"])
	}
	names := sectionNames(t, cfg, "clusters")
	if !hasName(names, "work") {
		t.Errorf("the user's own cluster was lost: %v", names)
	}
	if !hasName(names, "grant-aws-eks-prod") {
		t.Errorf("the generated cluster was not added: %v", names)
	}
}

func TestKubeconfigSetsCurrentContextOnlyWithOptIn(t *testing.T) {
	pinGrantPath(t, "/usr/local/bin/grant")

	dir := t.TempDir()
	target := filepath.Join(dir, "config")
	if err := os.WriteFile(target, []byte(preExistingKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewK8sKubeconfigCommandWithDeps(&mockAuthLoader{}, awsGenerator())
	if _, _, err := runKubeconfig(t, cmd, "--file", target, "--set-current-context"); err != nil {
		t.Fatalf("execute: %v", err)
	}

	data, _ := os.ReadFile(target) //nolint:gosec // test-controlled path
	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["current-context"] != "grant-aws-eks-prod" {
		t.Errorf("current-context = %v, want the generated context after opt-in", cfg["current-context"])
	}
}

func TestKubeconfigRewritesExecCommandToGrant(t *testing.T) {
	pinGrantPath(t, "/opt/bin/grant")

	target := filepath.Join(t.TempDir(), "config")
	cmd := NewK8sKubeconfigCommandWithDeps(&mockAuthLoader{}, awsGenerator())
	_, stderr, err := runKubeconfig(t, cmd, "--file", target)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	data, _ := os.ReadFile(target) //nolint:gosec // test-controlled path
	body := string(data)
	if !strings.Contains(body, "/opt/bin/grant") {
		t.Errorf("exec.command was not rewritten to the grant binary:\n%s", body)
	}
	if !strings.Contains(body, "exec-credential") {
		t.Errorf("exec args were not rewritten:\n%s", body)
	}
	if strings.Contains(body, "kubectl-login") {
		t.Errorf("the official CLI args survived the rewrite:\n%s", body)
	}
	if !strings.Contains(stderr, "Rewrote exec plugin") {
		t.Errorf("the rewrite should be reported on stderr, got:\n%s", stderr)
	}
}

func TestKubeconfigStdoutTouchesNoFile(t *testing.T) {
	pinGrantPath(t, "/usr/local/bin/grant")

	dir := t.TempDir()
	target := filepath.Join(dir, "config")
	if err := os.WriteFile(target, []byte(preExistingKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", target)

	cmd := NewK8sKubeconfigCommandWithDeps(&mockAuthLoader{}, awsGenerator())
	stdout, _, err := runKubeconfig(t, cmd, "--stdout")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(stdout, "grant-aws-eks-prod") {
		t.Errorf("stdout should carry the generated kubeconfig:\n%s", stdout)
	}

	data, _ := os.ReadFile(target) //nolint:gosec // test-controlled path
	if string(data) != preExistingKubeconfig {
		t.Errorf("--stdout must not touch any file, but the target changed:\n%s", data)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("--stdout wrote extra files: %d entries", len(entries))
	}
}

func TestKubeconfigHonoursKubeconfigEnvListForm(t *testing.T) {
	pinGrantPath(t, "/usr/local/bin/grant")

	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	for _, p := range []string{first, second} {
		if err := os.WriteFile(p, []byte(preExistingKubeconfig), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("KUBECONFIG", first+string(os.PathListSeparator)+second)

	cmd := NewK8sKubeconfigCommandWithDeps(&mockAuthLoader{}, awsGenerator())
	if _, _, err := runKubeconfig(t, cmd); err != nil {
		t.Fatalf("execute: %v", err)
	}

	firstData, _ := os.ReadFile(first)   //nolint:gosec // test-controlled path
	secondData, _ := os.ReadFile(second) //nolint:gosec // test-controlled path
	if !strings.Contains(string(firstData), "grant-aws-eks-prod") {
		t.Errorf("the first $KUBECONFIG entry was not written:\n%s", firstData)
	}
	if string(secondData) != preExistingKubeconfig {
		t.Errorf("only the first $KUBECONFIG entry may be written; the second changed:\n%s", secondData)
	}
}

func TestKubeconfigFilePermissionsAndBackup(t *testing.T) {
	pinGrantPath(t, "/usr/local/bin/grant")

	dir := t.TempDir()
	target := filepath.Join(dir, "config")
	if err := os.WriteFile(target, []byte(preExistingKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewK8sKubeconfigCommandWithDeps(&mockAuthLoader{}, awsGenerator())
	if _, stderr, err := runKubeconfig(t, cmd, "--file", target); err != nil {
		t.Fatalf("execute: %v\n%s", err, stderr)
	}

	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	// The mode half is POSIX-only: Go synthesizes Windows FileMode bits from a
	// single read-only attribute, so every ordinary file reads as 0666 there.
	// The backup half below is portable and keeps running on every platform.
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", fi.Mode().Perm())
	}

	backup, err := os.ReadFile(target + ".grant.bak") //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("no backup written: %v", err)
	}
	if string(backup) != preExistingKubeconfig {
		t.Error("the backup does not match the pre-merge content")
	}
}

func TestKubeconfigProviderSelection(t *testing.T) {
	pinGrantPath(t, "/usr/local/bin/grant")
	target := filepath.Join(t.TempDir(), "config")

	gen := awsGenerator()
	cmd := NewK8sKubeconfigCommandWithDeps(&mockAuthLoader{}, gen)
	if _, _, err := runKubeconfig(t, cmd, "--file", target, "--provider", "aws"); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(gen.gotCSPs) != 1 || gen.gotCSPs[0] != "aws" {
		t.Errorf("csps = %v, want [aws]", gen.gotCSPs)
	}

	gen2 := awsGenerator()
	cmd2 := NewK8sKubeconfigCommandWithDeps(&mockAuthLoader{}, gen2)
	if _, _, err := runKubeconfig(t, cmd2, "--file", target); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(gen2.gotCSPs) != len(k8s.SupportedCSPs) {
		t.Errorf("csps = %v, want all supported providers", gen2.gotCSPs)
	}
}

func TestKubeconfigRejectsUnsupportedProvider(t *testing.T) {
	cmd := NewK8sKubeconfigCommandWithDeps(&mockAuthLoader{}, awsGenerator())
	if _, _, err := runKubeconfig(t, cmd, "--provider", "gcp"); err == nil {
		t.Fatal("expected an unsupported-provider error")
	}
}

func TestKubeconfigReportsPartialFailures(t *testing.T) {
	pinGrantPath(t, "/usr/local/bin/grant")
	target := filepath.Join(t.TempDir(), "config")

	gen := &mockKubeconfigGenerator{
		configs:  map[string]string{"aws": generatedAWSKubeconfig},
		failures: []k8s.KubeconfigFailure{{CSP: "azure", Error: "not entitled"}},
	}
	cmd := NewK8sKubeconfigCommandWithDeps(&mockAuthLoader{}, gen)
	_, stderr, err := runKubeconfig(t, cmd, "--file", target)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(stderr, "azure kubeconfig generation failed") {
		t.Errorf("partial failure not reported:\n%s", stderr)
	}
}

func TestKubeconfigFailsWhenNothingGenerated(t *testing.T) {
	gen := &mockKubeconfigGenerator{
		configs:  map[string]string{},
		failures: []k8s.KubeconfigFailure{{CSP: "aws", Error: "boom"}},
	}
	cmd := NewK8sKubeconfigCommandWithDeps(&mockAuthLoader{}, gen)
	_, _, err := runKubeconfig(t, cmd, "--file", filepath.Join(t.TempDir(), "config"))
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want the provider failure surfaced", err)
	}
}

func TestKubeconfigJSONOutput(t *testing.T) {
	pinGrantPath(t, "/usr/local/bin/grant")
	setOutputFormat(t, "json")

	target := filepath.Join(t.TempDir(), "config")
	cmd := NewK8sKubeconfigCommandWithDeps(&mockAuthLoader{}, awsGenerator())
	stdout, _, err := runKubeconfig(t, cmd, "--file", target)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	var got kubeconfigOutput
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout)
	}
	if got.Path != target {
		t.Errorf("path = %q, want %q", got.Path, target)
	}
	if len(got.Added) != 3 {
		t.Errorf("added = %v, want 3 entries", got.Added)
	}
	if !hasName(got.Contexts, "grant-aws-eks-prod") {
		t.Errorf("contexts = %v", got.Contexts)
	}
}

func TestKubeconfigRequiresAuth(t *testing.T) {
	cmd := NewK8sKubeconfigCommandWithDeps(&mockAuthLoader{loadErr: errNotAuthenticated}, awsGenerator())
	if _, _, err := runKubeconfig(t, cmd, "--file", filepath.Join(t.TempDir(), "config")); err == nil ||
		!strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("err = %v", err)
	}
}

func sectionNames(t *testing.T, cfg map[string]any, section string) []string {
	t.Helper()
	list, _ := cfg[section].([]any)
	names := make([]string, 0, len(list))
	for _, item := range list {
		m, _ := item.(map[string]any)
		name, _ := m["name"].(string)
		names = append(names, name)
	}
	return names
}

func hasName(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}
