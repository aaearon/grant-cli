package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aaearon/grant-cli/internal/k8s"
	"github.com/spf13/cobra"
)

// mockCredentialProvider implements clusterCredentialProvider.
type mockCredentialProvider struct {
	cred        *k8s.ExecCredential
	err         error
	calls       int
	gotParams   k8s.ExecCredentialParams
	interactive []bool
}

func (m *mockCredentialProvider) ExecCredential(_ context.Context, p k8s.ExecCredentialParams) (*k8s.ExecCredential, error) {
	m.calls++
	m.gotParams = p
	m.interactive = append(m.interactive, p.Interactive)
	return m.cred, m.err
}

func execInfoJSON(t *testing.T, apiVersion string, interactive bool) string {
	t.Helper()
	payload := map[string]any{
		"apiVersion": apiVersion,
		"kind":       "ExecCredential",
		"spec":       map[string]any{"interactive": interactive},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func sampleCredential(expiry time.Time) *k8s.ExecCredential {
	return &k8s.ExecCredential{
		APIVersion: "client.authentication.k8s.io/v1beta1",
		Kind:       "ExecCredential",
		Status: k8s.ExecCredentialStatus{
			Token:               "k8s-aws-v1.abc",
			ExpirationTimestamp: expiry.UTC().Format(time.RFC3339),
		},
	}
}

// runExecCred executes the command capturing stdout and stderr separately so we
// can assert stdout carries the ExecCredential JSON and nothing else.
func runExecCred(t *testing.T, cmd *cobra.Command, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errBuf.String(), err
}

func TestExecCredentialStdoutIsOnlyJSON(t *testing.T) {
	// Verbose logging on: any log output must go to stderr, never stdout.
	oldVerbose := verbose
	defer func() { verbose = oldVerbose }()
	verbose = true

	provider := &mockCredentialProvider{cred: sampleCredential(time.Now().Add(time.Hour))}
	cmd := NewK8sExecCredentialCommandWithDeps(provider, nil,
		execInfoJSON(t, "client.authentication.k8s.io/v1beta1", true))

	stdout, _, err := runExecCred(t, cmd, "--csp", "aws", "--fqdn", "prod.eks.example")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	trimmed := strings.TrimSpace(stdout)
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		t.Fatalf("stdout must be exactly the ExecCredential JSON, got:\n%q", stdout)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(trimmed), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if got["kind"] != "ExecCredential" {
		t.Errorf("kind = %v", got["kind"])
	}

	// Exactly one JSON document, nothing appended.
	dec := json.NewDecoder(strings.NewReader(stdout))
	var first any
	if err := dec.Decode(&first); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.More() {
		t.Errorf("stdout contains trailing content after the ExecCredential JSON:\n%q", stdout)
	}
}

func TestExecCredentialAPIVersionNegotiation(t *testing.T) {
	tests := []struct {
		name       string
		apiVersion string
		wantErr    bool
	}{
		{name: "v1beta1", apiVersion: "client.authentication.k8s.io/v1beta1"},
		{name: "v1", apiVersion: "client.authentication.k8s.io/v1"},
		{name: "unknown version", apiVersion: "client.authentication.k8s.io/v2", wantErr: true},
		{name: "empty version", apiVersion: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The provider always returns v1beta1; the response must echo the request.
			provider := &mockCredentialProvider{cred: sampleCredential(time.Now().Add(time.Hour))}
			cmd := NewK8sExecCredentialCommandWithDeps(provider, nil, execInfoJSON(t, tt.apiVersion, true))

			stdout, _, err := runExecCred(t, cmd, "--csp", "aws", "--fqdn", "host")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error for apiVersion %q", tt.apiVersion)
				}
				if stdout != "" {
					t.Errorf("nothing may be written to stdout on error, got %q", stdout)
				}
				return
			}
			if err != nil {
				t.Fatalf("execute: %v", err)
			}

			var got map[string]any
			if err := json.Unmarshal([]byte(stdout), &got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got["apiVersion"] != tt.apiVersion {
				t.Errorf("apiVersion = %v, want the requested %q (never hardcoded)", got["apiVersion"], tt.apiVersion)
			}
		})
	}
}

func TestExecCredentialRequiresExecInfo(t *testing.T) {
	provider := &mockCredentialProvider{cred: sampleCredential(time.Now().Add(time.Hour))}
	cmd := NewK8sExecCredentialCommandWithDeps(provider, nil, "")

	stdout, _, err := runExecCred(t, cmd, "--csp", "aws", "--fqdn", "host")
	if err == nil {
		t.Fatal("expected an error when KUBERNETES_EXEC_INFO is absent")
	}
	if !strings.Contains(err.Error(), "KUBERNETES_EXEC_INFO") {
		t.Errorf("err = %v, want it to name the env var", err)
	}
	if stdout != "" {
		t.Errorf("stdout must stay empty on error, got %q", stdout)
	}
}

func TestExecCredentialRejectsMalformedExecInfo(t *testing.T) {
	provider := &mockCredentialProvider{cred: sampleCredential(time.Now().Add(time.Hour))}
	cmd := NewK8sExecCredentialCommandWithDeps(provider, nil, "{not json")

	if _, _, err := runExecCred(t, cmd, "--csp", "aws", "--fqdn", "host"); err == nil {
		t.Fatal("expected an error for malformed KUBERNETES_EXEC_INFO")
	}
}

func TestExecCredentialInteractiveModePropagated(t *testing.T) {
	for _, interactive := range []bool{true, false} {
		provider := &mockCredentialProvider{cred: sampleCredential(time.Now().Add(time.Hour))}
		cmd := NewK8sExecCredentialCommandWithDeps(provider, nil,
			execInfoJSON(t, "client.authentication.k8s.io/v1beta1", interactive))

		if _, _, err := runExecCred(t, cmd, "--csp", "aws", "--fqdn", "host"); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if provider.gotParams.Interactive != interactive {
			t.Errorf("Interactive = %v, want %v", provider.gotParams.Interactive, interactive)
		}
	}
}

// interactive-forbidden + cache miss must fail cleanly, not hang on a browser flow.
func TestExecCredentialNonInteractiveCacheMissFailsCleanly(t *testing.T) {
	provider := &mockCredentialProvider{
		err: k8s.ErrInteractionRequired,
	}
	cmd := NewK8sExecCredentialCommandWithDeps(provider, nil,
		execInfoJSON(t, "client.authentication.k8s.io/v1beta1", false))

	stdout, _, err := runExecCred(t, cmd, "--csp", "aws", "--fqdn", "host")
	if !errors.Is(err, k8s.ErrInteractionRequired) {
		t.Fatalf("err = %v, want ErrInteractionRequired", err)
	}
	if stdout != "" {
		t.Errorf("stdout must stay empty on error, got %q", stdout)
	}
}

// interactive-forbidden + cache hit must succeed without calling the provider.
func TestExecCredentialNonInteractiveCacheHitSucceeds(t *testing.T) {
	dir := t.TempDir()
	credCache := k8s.NewCredentialCache(dir)
	key := k8s.CredentialKey{CSP: "aws", FQDN: "host", RoleID: "r"}
	if err := credCache.Put(key, sampleCredential(time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	provider := &mockCredentialProvider{err: k8s.ErrInteractionRequired}
	cmd := NewK8sExecCredentialCommandWithDeps(provider, credCache,
		execInfoJSON(t, "client.authentication.k8s.io/v1beta1", false))

	stdout, _, err := runExecCred(t, cmd, "--csp", "aws", "--fqdn", "host", "--role-id", "r")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if provider.calls != 0 {
		t.Errorf("provider called %d times, want 0 (cache hit)", provider.calls)
	}
	if !strings.Contains(stdout, "k8s-aws-v1.abc") {
		t.Errorf("cached token not replayed: %s", stdout)
	}
}

func TestExecCredentialCachesAndRefetchesAfterExpiry(t *testing.T) {
	dir := t.TempDir()
	credCache := k8s.NewCredentialCache(dir)

	expiry := time.Now().Add(2 * time.Minute)
	provider := &mockCredentialProvider{cred: sampleCredential(expiry)}
	info := execInfoJSON(t, "client.authentication.k8s.io/v1beta1", true)

	// First call: cache miss, provider invoked, credential cached.
	cmd := NewK8sExecCredentialCommandWithDeps(provider, credCache, info)
	if _, _, err := runExecCred(t, cmd, "--csp", "aws", "--fqdn", "host"); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.calls)
	}

	// Second call: cache hit, provider not invoked again.
	cmd = NewK8sExecCredentialCommandWithDeps(provider, credCache, info)
	if _, _, err := runExecCred(t, cmd, "--csp", "aws", "--fqdn", "host"); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if provider.calls != 1 {
		t.Errorf("provider calls = %d, want it to still be 1 (cached)", provider.calls)
	}

	// Once the stamped expiry passes, the credential is refetched.
	files, _ := filepath.Glob(filepath.Join(dir, "execcred_*.json"))
	if len(files) != 1 {
		t.Fatalf("expected exactly one cache file, got %v", files)
	}
	expired := sampleCredential(time.Now().Add(-time.Minute))
	data, _ := json.Marshal(expired)
	if err := os.WriteFile(files[0], data, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd = NewK8sExecCredentialCommandWithDeps(provider, credCache, info)
	if _, _, err := runExecCred(t, cmd, "--csp", "aws", "--fqdn", "host"); err != nil {
		t.Fatalf("third call: %v", err)
	}
	if provider.calls != 2 {
		t.Errorf("provider calls = %d, want 2 after the cached credential expired", provider.calls)
	}
}

func TestExecCredentialCacheFilePermissions(t *testing.T) {
	dir := t.TempDir()
	credCache := k8s.NewCredentialCache(dir)
	provider := &mockCredentialProvider{cred: sampleCredential(time.Now().Add(time.Hour))}

	cmd := NewK8sExecCredentialCommandWithDeps(provider, credCache,
		execInfoJSON(t, "client.authentication.k8s.io/v1beta1", true))
	if _, _, err := runExecCred(t, cmd, "--csp", "aws", "--fqdn", "host"); err != nil {
		t.Fatalf("execute: %v", err)
	}

	files, _ := filepath.Glob(filepath.Join(dir, "execcred_*.json"))
	if len(files) != 1 {
		t.Fatalf("expected one cache file, got %v", files)
	}
	fi, err := os.Stat(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("cache file mode = %o, want 0600", fi.Mode().Perm())
	}
}

// The buffer is baked in once by the credential source; the command replays the
// stamped expirationTimestamp verbatim.
func TestExecCredentialDoesNotAdjustExpiry(t *testing.T) {
	expiry := time.Now().Add(37 * time.Minute).UTC().Truncate(time.Second)
	provider := &mockCredentialProvider{cred: sampleCredential(expiry)}
	cmd := NewK8sExecCredentialCommandWithDeps(provider, nil,
		execInfoJSON(t, "client.authentication.k8s.io/v1beta1", true))

	stdout, _, err := runExecCred(t, cmd, "--csp", "aws", "--fqdn", "host")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	var got k8s.ExecCredential
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status.ExpirationTimestamp != expiry.Format(time.RFC3339) {
		t.Errorf("expirationTimestamp = %q, want the source value %q unchanged",
			got.Status.ExpirationTimestamp, expiry.Format(time.RFC3339))
	}
}

func TestExecCredentialValidatesFlags(t *testing.T) {
	info := execInfoJSON(t, "client.authentication.k8s.io/v1beta1", true)
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing fqdn", args: []string{"--csp", "aws"}},
		{name: "missing csp", args: []string{"--fqdn", "host"}},
		{name: "unsupported csp", args: []string{"--csp", "gcp", "--fqdn", "host"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockCredentialProvider{cred: sampleCredential(time.Now().Add(time.Hour))}
			cmd := NewK8sExecCredentialCommandWithDeps(provider, nil, info)
			if _, _, err := runExecCred(t, cmd, tt.args...); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestExecCredentialIsHidden(t *testing.T) {
	cmd := newK8sExecCredentialCommand(nil)
	if !cmd.Hidden {
		t.Error("exec-credential must be Hidden so it does not appear in help")
	}
}
