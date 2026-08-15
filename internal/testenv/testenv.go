// Package testenv redirects every environment variable grant uses to locate
// user state at a throwaway temporary directory, so running the test suite can
// never read or clobber the developer's real ~/.grant or ~/.idsec.
//
// It is a normal (non-test) package so that TestMain functions in several
// packages can share it, but it is imported only from _test.go files and so
// never links into the shipped binary. It deliberately does NOT import
// "testing": that import belongs to test binaries, and keeping it out means
// no importer inherits the testing flag set.
//
// # What the assertions actually prove
//
// AssertSandboxed verifies that the *configured destinations* — the paths
// config.ConfigDir, config.ConfigPath, cache.CacheDir and
// profiles.GetProfilesFolder resolve to — all sit under the sandbox root. That
// is all it proves. It does NOT prove that no code wrote outside the sandbox:
// it cannot see a future direct os.UserHomeDir call, a hardcoded path, or a
// dependency that writes via some other variable, and it cannot detect reads at
// all. A filesystem snapshot-diff gate was considered and rejected — a
// concurrently running real `grant` false-positives with certainty, size+mtime
// misses same-size rewrites, and reads stay invisible either way.
package testenv

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aaearon/grant-cli/internal/cache"
	"github.com/aaearon/grant-cli/internal/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

// redirectedVars lists every environment variable Run overrides, in the order
// it sets them. Each one is a way for some resolver to reach the real home:
//
//   - HOME               — POSIX os.UserHomeDir, and the SDK profile loader,
//     which reads os.Getenv("HOME") directly on every platform.
//   - USERPROFILE        — Go's Windows os.UserHomeDir reads USERPROFILE, then
//     HOMEDRIVE+HOMEPATH. It never consults HOME, so
//     redirecting HOME alone leaves the Windows CI leg
//     pointed at the real profile directory.
//   - XDG_CONFIG_HOME    — consulted by third-party config helpers.
//   - IDSEC_PROFILES_FOLDER — takes precedence over HOME in the SDK loader.
//   - GRANT_CONFIG       — overrides config.ConfigPath.
var redirectedVars = []string{
	"HOME",
	"USERPROFILE",
	"XDG_CONFIG_HOME",
	"IDSEC_PROFILES_FOLDER",
	"GRANT_CONFIG",
}

// sandboxRoot is the active sandbox root, or "" when Run is not executing.
var sandboxRoot string

// Root returns the active sandbox root directory, or "" outside of Run.
func Root() string { return sandboxRoot }

// Run creates a temporary sandbox root, redirects every variable in
// redirectedVars beneath it, invokes run, then restores the previous
// environment and removes the sandbox. It returns run's exit code so callers
// can write:
//
//	func TestMain(m *testing.M) { os.Exit(testenv.Run(m.Run)) }
//
// Setting the variables here — before m.Run — is what makes this compatible
// with the t.Parallel() call sites throughout internal/: os.Setenv has no
// parallel restriction, whereas t.Setenv panics in a parallel test.
func Run(run func() int) int {
	root, err := os.MkdirTemp("", "grant-testenv-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "testenv: failed to create sandbox root: %v\n", err)
		return 1
	}

	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "testenv: failed to create sandbox home: %v\n", err)
		_ = os.RemoveAll(root)
		return 1
	}

	values := map[string]string{
		"HOME":                  home,
		"USERPROFILE":           home,
		"XDG_CONFIG_HOME":       filepath.Join(home, ".config"),
		"IDSEC_PROFILES_FOLDER": filepath.Join(home, ".idsec", "profiles"),
		"GRANT_CONFIG":          filepath.Join(home, ".grant", "config.yaml"),
	}

	restore := make(map[string]*string, len(redirectedVars))
	for _, k := range redirectedVars {
		if v, ok := os.LookupEnv(k); ok {
			prev := v
			restore[k] = &prev
		} else {
			restore[k] = nil
		}
		if err := os.Setenv(k, values[k]); err != nil {
			fmt.Fprintf(os.Stderr, "testenv: failed to set %s: %v\n", k, err)
			restoreEnv(restore)
			_ = os.RemoveAll(root)
			return 1
		}
	}

	sandboxRoot = root
	code := run()
	sandboxRoot = ""

	restoreEnv(restore)
	_ = os.RemoveAll(root)
	return code
}

// restoreEnv puts back the captured values; a nil entry means the variable was
// originally unset and must be unset again rather than set to "".
func restoreEnv(restore map[string]*string) {
	for k, v := range restore {
		if v == nil {
			_ = os.Unsetenv(k)
			continue
		}
		_ = os.Setenv(k, *v)
	}
}

// TB is the subset of *testing.T that AssertSandboxed needs. Accepting an
// interface is what lets this file stay free of the "testing" import.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
}

// AssertSandboxed checks that every path grant resolves for user state lands
// under the active sandbox root. See the package comment for exactly what this
// does and does not prove.
func AssertSandboxed(t TB) {
	t.Helper()

	root := Root()
	if root == "" {
		t.Errorf("testenv.AssertSandboxed called outside testenv.Run; no sandbox is active")
		return
	}

	configDir, err := config.ConfigDir()
	if err != nil {
		t.Errorf("config.ConfigDir() failed inside sandbox: %v", err)
	} else {
		assertUnder(t, "config.ConfigDir()", configDir, root)
	}

	configPath, err := config.ConfigPath()
	if err != nil {
		t.Errorf("config.ConfigPath() failed inside sandbox: %v", err)
	} else {
		assertUnder(t, "config.ConfigPath()", configPath, root)
	}

	cacheDir, err := cache.CacheDir()
	if err != nil {
		t.Errorf("cache.CacheDir() failed inside sandbox: %v", err)
	} else {
		assertUnder(t, "cache.CacheDir()", cacheDir, root)
	}

	assertUnder(t, "profiles.GetProfilesFolder()", profiles.GetProfilesFolder(), root)
}

// assertUnder reports a failure unless got is root itself or below it.
func assertUnder(t TB, what, got, root string) {
	t.Helper()

	cleanGot := filepath.Clean(got)
	cleanRoot := filepath.Clean(root)
	if cleanGot == cleanRoot || strings.HasPrefix(cleanGot, cleanRoot+string(filepath.Separator)) {
		return
	}
	t.Errorf("%s = %q, which is outside the test sandbox %q; the suite would touch real user state", what, got, root)
}
