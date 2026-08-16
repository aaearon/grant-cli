//go:build integration

package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/testenv"
)

// testBinary is the compiled grant binary under test. It lives in a private
// temp directory with a unique name rather than the old shared ../grant-test,
// so two concurrent runs (or a stale artifact from a killed run) cannot
// interfere with each other or leave debris in the repo.
var testBinary string

// goEnvPassthrough carries the Go tool's own directories into the sandboxed
// build. They are resolved BEFORE testenv.Run redirects HOME, because GOCACHE
// and GOMODCACHE default to locations under the user's home: without this the
// build inside the sandbox would start from an empty module cache and need the
// network.
//
// GOENV is in the list for the same reason and one more. The child `go build`
// locates its env file through os.UserConfigDir: $XDG_CONFIG_HOME/go/env on
// Linux — which the redirect points at an empty sandbox — but %AppData%\go\env
// on Windows, which is not redirected at all. Without pinning GOENV the two CI
// legs resolve different files, and any `go env -w GOPROXY=…` / `GOFLAGS` /
// `GOPRIVATE` the developer or runner configured is silently dropped on Linux.
var goEnvPassthrough []string

func TestMain(m *testing.M) {
	goEnvPassthrough = resolveGoEnv("GOCACHE", "GOMODCACHE", "GOPATH", "GOENV")

	os.Exit(testenv.Run(func() int {
		dir, err := os.MkdirTemp("", "grant-integration-bin-")
		if err != nil {
			fmt.Fprintf(os.Stderr, "integration: failed to create binary dir: %v\n", err)
			return 1
		}
		defer func() { _ = os.RemoveAll(dir) }()

		name := "grant-integration-test"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		testBinary = filepath.Join(dir, name)

		build := exec.Command("go", "build", "-o", testBinary, "..")
		build.Env = append(os.Environ(), goEnvPassthrough...)
		if out, err := build.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "integration: failed to build binary: %v\n%s\n", err, out)
			return 1
		}

		// The in-process cmd unit tests compile into this binary too; give
		// them the same disabled bootstrap they get in the default build.
		installBootstrapStub()

		return m.Run()
	}))
}

// resolveGoEnv returns KEY=VALUE strings for the named `go env` keys.
func resolveGoEnv(keys ...string) []string {
	out, err := exec.Command("go", append([]string{"env"}, keys...)...).Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
	env := make([]string, 0, len(keys))
	for i, k := range keys {
		if i >= len(lines) || lines[i] == "" {
			continue
		}
		env = append(env, k+"="+lines[i])
	}
	return env
}

// result is the outcome of one child invocation.
type result struct {
	output   string
	exitCode int
}

// contains reports whether the combined output contains want.
func (r result) contains(want string) bool { return strings.Contains(r.output, want) }

// runGrant executes the built binary with the process's (already sandboxed)
// environment plus extra, with stdin closed so no interactive prompt can
// block. It returns the combined output and the real exit code.
func runGrant(t *testing.T, extraEnv []string, args ...string) result {
	t.Helper()

	cmd := exec.Command(testBinary, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdin = nil // closed: never a TTY, and never blocks on a prompt

	out, err := cmd.CombinedOutput()

	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running %v: %v\noutput:\n%s", args, err, out)
		}
		code = exitErr.ExitCode()
	}

	r := result{output: string(out), exitCode: code}

	// A panic satisfies almost any keyword-based assertion, which is exactly
	// how the previous version of these tests could pass on a crash.
	if r.contains("panic:") || r.contains("goroutine 1 [running]:") {
		t.Fatalf("binary panicked on %v (exit %d):\n%s", args, code, out)
	}
	return r
}

// isolatedEnv points config and credentials at a fresh per-test directory on
// top of the process-wide testenv sandbox.
func isolatedEnv(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	return []string{
		"HOME=" + dir,
		"USERPROFILE=" + dir,
		"GRANT_CONFIG=" + filepath.Join(dir, "config.yaml"),
		"IDSEC_PROFILES_FOLDER=" + filepath.Join(dir, "profiles"),
		// The SDK reads these two absolute-path overrides directly, bypassing
		// the HOME fallback, and forces its file keyring on any non-empty
		// IDSEC_BASIC_KEYRING. Without them a pre-existing value in the
		// developer's or CI environment sends the subprocess's keyring and log
		// writes outside the sandbox.
		"IDSEC_KEYRING_FOLDER=" + filepath.Join(dir, "keyring"),
		"IDSEC_FILE_LOG_PATH=" + filepath.Join(dir, "logs", "idsec.log"),
		"IDSEC_BASIC_KEYRING=1",
	}
}

func TestIntegration_Help(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantText []string
	}{
		{
			name:     "root help",
			args:     []string{"--help"},
			wantText: []string{"grant", "Available Commands:", "configure", "login", "status"},
		},
		{
			name:     "short help flag",
			args:     []string{"-h"},
			wantText: []string{"grant", "Available Commands:"},
		},
		{
			name:     "help command",
			args:     []string{"help"},
			wantText: []string{"grant", "Available Commands:"},
		},
		{
			name:     "root elevation help",
			args:     []string{"--help"},
			wantText: []string{"--provider", "--target", "--role", "--favorite"},
		},
		{
			name:     "configure help",
			args:     []string{"configure", "--help"},
			wantText: []string{"configure", "Identity URL", "username"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runGrant(t, isolatedEnv(t), tt.args...)
			// Help is a success path: exit 0, exactly.
			if got.exitCode != 0 {
				t.Fatalf("exit code = %d, want 0\noutput:\n%s", got.exitCode, got.output)
			}
			for _, want := range tt.wantText {
				if !got.contains(want) {
					t.Errorf("output missing %q, got:\n%s", want, got.output)
				}
			}
		})
	}
}

func TestIntegration_Version(t *testing.T) {
	got := runGrant(t, isolatedEnv(t), "version")
	if got.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0\noutput:\n%s", got.exitCode, got.output)
	}

	for _, field := range []string{"grant version", "commit:", "built:"} {
		if !got.contains(field) {
			t.Errorf("output missing %q, got:\n%s", field, got.output)
		}
	}
	// The integration binary is built without -ldflags, so the version stays
	// at its compiled-in default. Assert the version line specifically: the
	// binary always prints "commit: unknown" for a non-ldflags build, so an
	// `|| contains("unknown")` arm would make this assertion true regardless
	// of the version string.
	if !got.contains("grant version dev") {
		t.Errorf("expected a dev build banner, got:\n%s", got.output)
	}
}

func TestIntegration_ElevateWithoutLogin(t *testing.T) {
	got := runGrant(t, isolatedEnv(t), "--provider", "azure")

	if got.exitCode != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", got.exitCode, got.output)
	}
	// Exact text, not a keyword soup. With an empty sandbox profile directory
	// the SDK authenticator refuses before any network call, and the non-
	// verbose hint is part of the contract.
	for _, want := range []string{
		"authentication failed: either a profile or a specific auth profile must be supplied",
		"Hint: re-run with --verbose for more details",
	} {
		if !got.contains(want) {
			t.Errorf("output missing %q, got:\n%s", want, got.output)
		}
	}
}

func TestIntegration_StatusWithoutLogin(t *testing.T) {
	got := runGrant(t, isolatedEnv(t), "status")

	if got.exitCode != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", got.exitCode, got.output)
	}
	if want := "authentication failed: either a profile or a specific auth profile must be supplied"; !got.contains(want) {
		t.Errorf("output missing %q, got:\n%s", want, got.output)
	}
	// It must never claim an identity it does not have.
	if got.contains("Username:") {
		t.Errorf("status printed a username without authentication:\n%s", got.output)
	}
}

func TestIntegration_FavoritesList(t *testing.T) {
	got := runGrant(t, isolatedEnv(t), "favorites", "list")

	if got.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (an empty favorites list is a success)\noutput:\n%s",
			got.exitCode, got.output)
	}
	if !got.contains("No favorites") {
		t.Errorf("output missing %q, got:\n%s", "No favorites", got.output)
	}
}

func TestIntegration_FavoritesAddWithFlags(t *testing.T) {
	env := isolatedEnv(t)

	added := runGrant(t, env, "favorites", "add", "test-fav", "--target", "sub-123", "--role", "Contributor")
	if added.exitCode != 0 {
		t.Fatalf("favorites add exit code = %d, want 0\noutput:\n%s", added.exitCode, added.output)
	}
	if !added.contains("Added favorite") {
		t.Errorf("output missing %q, got:\n%s", "Added favorite", added.output)
	}

	listed := runGrant(t, env, "favorites", "list")
	if listed.exitCode != 0 {
		t.Fatalf("favorites list exit code = %d, want 0\noutput:\n%s", listed.exitCode, listed.output)
	}
	for _, want := range []string{"test-fav", "azure/sub-123/Contributor"} {
		if !listed.contains(want) {
			t.Errorf("favorites list missing %q, got:\n%s", want, listed.output)
		}
	}
}

// TestIntegration_FavoritesAddWithoutTTYFailsBeforeAuth is the end-to-end
// counterpart of TestFavoritesAdd_NonInteractiveGuard: with stdin closed the
// command must refuse immediately with the non-interactive hint, and must NOT
// reach the profile load / authentication it used to attempt first.
func TestIntegration_FavoritesAddWithoutTTYFailsBeforeAuth(t *testing.T) {
	got := runGrant(t, isolatedEnv(t), "favorites", "add", "test-fav")

	if got.exitCode != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", got.exitCode, got.output)
	}
	for _, want := range []string{"interactive selection requires a terminal", "--target", "--role"} {
		if !got.contains(want) {
			t.Errorf("output missing %q, got:\n%s", want, got.output)
		}
	}
	if got.contains("failed to load profile") || got.contains("authentication failed") {
		t.Errorf("favorites add reached authentication before the non-interactive guard:\n%s", got.output)
	}
}

func TestIntegration_InvalidCommand(t *testing.T) {
	got := runGrant(t, isolatedEnv(t), "nonexistent-command")

	if got.exitCode != 1 {
		t.Fatalf("exit code = %d, want 1\noutput:\n%s", got.exitCode, got.output)
	}
	if want := `unknown command "nonexistent-command" for "grant"`; !got.contains(want) {
		t.Errorf("output missing %q, got:\n%s", want, got.output)
	}
}

// TestIntegration_SandboxIsolation asserts the harness itself is sandboxed, so
// a regression in TestMain surfaces here rather than as writes to the
// developer's real home directory.
func TestIntegration_SandboxIsolation(t *testing.T) {
	testenv.AssertSandboxed(t)
}
