// Package testenv redirects the environment variables grant and its SDK use to
// locate user state at a throwaway temporary directory, so running the test
// suite can never read or clobber the developer's real ~/.grant or ~/.idsec.
//
// # What it does not cover
//
// The redirect is a list of known variables (see redirectedVars), not a
// containment boundary. Anything that reaches user state by another route
// escapes it:
//
//   - A direct os.UserHomeDir call is covered only because HOME/USERPROFILE are
//     redirected; a hardcoded path or a newly-added SDK variable is not covered
//     at all, and nothing here discovers one automatically.
//   - The OS keyring is a daemon, not a path, so no environment redirect can
//     sandbox it. Run sets IDSEC_BASIC_KEYRING=1 to force the SDK's file
//     backend into the sandboxed IDSEC_KEYRING_FOLDER instead. If a future SDK
//     stops honoring that variable, keyring access leaves the sandbox again
//     and nothing here will notice.
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
// config.ConfigDir, config.ConfigPath, cache.CacheDir,
// profiles.GetProfilesFolder, the SDK keyring folder and the SDK file-log path
// resolve to — all sit under the sandbox root, and that IDSEC_BASIC_KEYRING is
// set so the file keyring is the one in use. That
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
//   - XDG_CONFIG_HOME    — speculative/defensive. Nothing in grant or in the
//     pinned SDK reads it today (`rg XDG_` finds only this
//     comment and testenv's own tests). It is redirected
//     because it is the conventional escape hatch a config
//     helper would reach for, and a redirect costs nothing.
//   - IDSEC_PROFILES_FOLDER — takes precedence over HOME in the SDK loader.
//   - GRANT_CONFIG       — overrides config.ConfigPath.
//   - IDSEC_KEYRING_FOLDER — overrides the SDK file-keyring folder outright
//     (pkg/common/keyring/idsec_basic_keyring.go), bypassing
//     its HOME fallback. A pre-existing value in the
//     developer's or CI environment would otherwise put
//     keyring writes outside the sandbox.
//   - IDSEC_FILE_LOG_PATH — overrides the SDK's file-log destination
//     (pkg/config, consumed in pkg/common/idsec_logger.go),
//     whose parent directory the SDK MkdirAll's.
//   - IDSEC_BASIC_KEYRING — not a path: any non-empty value forces the SDK's
//     file keyring. Without it, a plain Linux box with
//     DBUS_SESSION_BUS_ADDRESS set selects the real
//     libsecret store, which no path redirect can sandbox.
var redirectedVars = []string{
	"HOME",
	"USERPROFILE",
	"XDG_CONFIG_HOME",
	"IDSEC_PROFILES_FOLDER",
	"GRANT_CONFIG",
	"IDSEC_KEYRING_FOLDER",
	"IDSEC_FILE_LOG_PATH",
	"IDSEC_BASIC_KEYRING",
}

// nonPathVars are the entries of redirectedVars whose value is a mode switch
// rather than a filesystem path, so "must resolve under the sandbox root" does
// not apply to them.
var nonPathVars = map[string]bool{
	"IDSEC_BASIC_KEYRING": true,
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
		"IDSEC_KEYRING_FOLDER":  filepath.Join(home, ".idsec", "cache", "keyring"),
		"IDSEC_FILE_LOG_PATH":   filepath.Join(home, ".idsec", "logs", "idsec.log"),
		"IDSEC_BASIC_KEYRING":   "1",
	}

	// Deferred so a panic inside run — a -race detection, a stray panic in a
	// test — still restores the environment and removes the sandbox instead of
	// leaking the directory and leaving the process redirected.
	restore := make(map[string]*string, len(redirectedVars))
	defer func() {
		restoreEnv(restore)
		_ = os.RemoveAll(root)
	}()

	for _, k := range redirectedVars {
		if v, ok := os.LookupEnv(k); ok {
			prev := v
			restore[k] = &prev
		} else {
			restore[k] = nil
		}
		if err := os.Setenv(k, values[k]); err != nil {
			fmt.Fprintf(os.Stderr, "testenv: failed to set %s: %v\n", k, err)
			return 1
		}
	}

	// Save and restore rather than clearing: a nested Run must hand the outer
	// run's root back, not "".
	prevRoot := sandboxRoot
	sandboxRoot = root
	defer func() { sandboxRoot = prevRoot }()

	return run()
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
	assertUnder(t, "SDK keyring folder", keyringFolder(), root)
	assertUnder(t, "SDK file log path", fileLogPath(), root)

	if os.Getenv("IDSEC_BASIC_KEYRING") == "" {
		t.Errorf("IDSEC_BASIC_KEYRING is empty; the SDK may select the real OS keyring, which no path redirect can sandbox")
	}
}

// keyringFolder mirrors the SDK's keyring folder resolution
// (pkg/common/keyring/idsec_basic_keyring.go NewIdsecBasicKeyring): the
// IDSEC_KEYRING_FOLDER override, else DefaultBasicKeyringFolder under HOME.
// It is reimplemented rather than called because the SDK constructor creates
// the directory as a side effect, which an assertion must not do.
func keyringFolder() string {
	if folder := os.Getenv("IDSEC_KEYRING_FOLDER"); folder != "" {
		return folder
	}
	return filepath.Join(os.Getenv("HOME"), ".idsec", "cache", "keyring")
}

// fileLogPath mirrors the SDK's file-log resolution (pkg/common/idsec_logger.go
// resolveFileLogWriter): the IDSEC_FILE_LOG_PATH override, else a default under
// os.UserHomeDir. The SDK MkdirAll's this path's parent.
func fileLogPath() string {
	if p := strings.TrimSpace(os.Getenv("IDSEC_FILE_LOG_PATH")); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".idsec", "logs", "idsec.log")
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
