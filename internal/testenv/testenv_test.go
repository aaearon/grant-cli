package testenv

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// recordingTB implements TB and records the failures reported to it, so the
// assertion helpers can be tested without failing the enclosing test.
type recordingTB struct {
	helperCalls int
	errs        []string
}

func (r *recordingTB) Helper() { r.helperCalls++ }

func (r *recordingTB) Errorf(format string, args ...any) {
	r.errs = append(r.errs, format)
	_ = args
}

// wantRedirectedVars is an explicit literal, deliberately NOT derived from
// redirectedVars. The previous version of this test ranged over redirectedVars
// itself, so deleting an entry merely checked one fewer thing; a drop-one
// mutation on four of the five entries then passed the whole suite.
var wantRedirectedVars = []string{
	"HOME",
	"USERPROFILE",
	"XDG_CONFIG_HOME",
	"IDSEC_PROFILES_FOLDER",
	"GRANT_CONFIG",
	"IDSEC_KEYRING_FOLDER",
	"IDSEC_FILE_LOG_PATH",
	"IDSEC_BASIC_KEYRING",
}

// TestRedirectedVarsIsExactlyTheExpectedSet pins the membership of
// redirectedVars. Adding a variable to the production list without adding it
// here is a deliberate speed bump: the new entry needs a hostile-value case in
// TestRun_OverridesPreExistingHostileValues too.
//
// Not parallel: kept serial with the rest of the file.
func TestRedirectedVarsIsExactlyTheExpectedSet(t *testing.T) {
	if !slices.Equal(redirectedVars, wantRedirectedVars) {
		t.Errorf("redirectedVars = %q, want exactly %q", redirectedVars, wantRedirectedVars)
	}
}

// Not parallel: mutates process-wide environment variables.
func TestRun_RedirectsAllHomeEnvVars(t *testing.T) {
	var (
		gotRoot string
		seen    = map[string]string{}
	)

	code := Run(func() int {
		gotRoot = Root()
		for _, k := range wantRedirectedVars {
			seen[k] = os.Getenv(k)
		}
		return 7
	})

	if code != 7 {
		t.Errorf("Run returned %d, want the code from run()", code)
	}
	if gotRoot == "" {
		t.Fatal("Root() was empty inside run()")
	}

	for _, k := range wantRedirectedVars {
		v := seen[k]
		if v == "" {
			t.Errorf("%s was empty inside run(); every redirected var must be set", k)
			continue
		}
		if nonPathVars[k] {
			continue // a mode switch, not a path: nothing to locate under the root
		}
		if !strings.HasPrefix(v, gotRoot) {
			t.Errorf("%s = %q, want a path under the sandbox root %q", k, v, gotRoot)
		}
	}
}

// TestRun_OverridesPreExistingHostileValues is the case that gives each entry
// in redirectedVars its own failing signal. Every var is pre-set to a path
// outside any sandbox before Run — exactly the state a developer or CI runner
// with the variable already exported is in — and each must come back
// overridden. With HOME redirected the other vars' *fallbacks* already land
// in-sandbox, so a pre-existing value is the only thing that distinguishes a
// redirected var from an unredirected one.
//
// Not parallel: mutates process-wide environment variables.
func TestRun_OverridesPreExistingHostileValues(t *testing.T) {
	hostile := t.TempDir() // outside any sandbox root, by construction

	for _, k := range wantRedirectedVars {
		t.Setenv(k, filepath.Join(hostile, strings.ToLower(k)))
	}

	seen := map[string]string{}
	var gotRoot string
	Run(func() int {
		gotRoot = Root()
		for _, k := range wantRedirectedVars {
			seen[k] = os.Getenv(k)
		}
		return 0
	})

	if gotRoot == "" {
		t.Fatal("Root() was empty inside run()")
	}

	for _, k := range wantRedirectedVars {
		got := seen[k]
		if strings.HasPrefix(got, hostile) {
			t.Errorf("%s = %q inside the sandbox; Run did not override the pre-existing value", k, got)
			continue
		}
		if nonPathVars[k] {
			if got == "" {
				t.Errorf("%s was empty inside the sandbox, want a non-empty override", k)
			}
			continue
		}
		if !strings.HasPrefix(got, gotRoot) {
			t.Errorf("%s = %q, want a path under the sandbox root %q", k, got, gotRoot)
		}
	}
}

// TestAssertSandboxed_FailsOnAHostileKeyringFolder is the concrete escape the
// package comment used to deny: IDSEC_KEYRING_FOLDER overrides the file-keyring
// folder outright, bypassing the HOME fallback, so before it joined
// redirectedVars the SDK created a keyring folder outside the sandbox while
// AssertSandboxed reported zero failures.
//
// Not parallel: mutates process-wide environment variables.
func TestAssertSandboxed_FailsOnAHostileKeyringFolder(t *testing.T) {
	escapee := t.TempDir()

	Run(func() int {
		//nolint:usetesting // t.Setenv's cleanup would fire after Run restores.
		if err := os.Setenv("IDSEC_KEYRING_FOLDER", escapee); err != nil {
			t.Errorf("Setenv: %v", err)
			return 1
		}
		rec := &recordingTB{}
		AssertSandboxed(rec)
		if len(rec.errs) != 1 {
			t.Errorf("AssertSandboxed reported %d failures, want exactly 1 (the escaped keyring folder): %v",
				len(rec.errs), rec.errs)
		}
		return 0
	})
}

// Not parallel: mutates process-wide environment variables.
func TestAssertSandboxed_FailsOnAHostileFileLogPath(t *testing.T) {
	escapee := filepath.Join(t.TempDir(), "idsec.log")

	Run(func() int {
		//nolint:usetesting // t.Setenv's cleanup would fire after Run restores.
		if err := os.Setenv("IDSEC_FILE_LOG_PATH", escapee); err != nil {
			t.Errorf("Setenv: %v", err)
			return 1
		}
		rec := &recordingTB{}
		AssertSandboxed(rec)
		if len(rec.errs) != 1 {
			t.Errorf("AssertSandboxed reported %d failures, want exactly 1 (the escaped file log path): %v",
				len(rec.errs), rec.errs)
		}
		return 0
	})
}

// Not parallel: mutates process-wide environment variables.
func TestAssertSandboxed_FailsWhenBasicKeyringIsNotForced(t *testing.T) {
	Run(func() int {
		//nolint:usetesting // t.Setenv's cleanup would fire after Run restores.
		if err := os.Setenv("IDSEC_BASIC_KEYRING", ""); err != nil {
			t.Errorf("Setenv: %v", err)
			return 1
		}
		rec := &recordingTB{}
		AssertSandboxed(rec)
		if len(rec.errs) != 1 {
			t.Errorf("AssertSandboxed reported %d failures, want exactly 1 (basic keyring not forced): %v",
				len(rec.errs), rec.errs)
		}
		return 0
	})
}

// Not parallel: mutates process-wide environment variables.
func TestRun_RestoresPreviousEnvironment(t *testing.T) {
	const sentinel = "/sentinel-home-value"
	t.Setenv("HOME", sentinel)
	// GRANT_CONFIG is deliberately left unset so we can prove an unset var
	// stays unset rather than being restored as an empty string.
	if err := os.Unsetenv("GRANT_CONFIG"); err != nil {
		t.Fatalf("Unsetenv: %v", err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("GRANT_CONFIG") })

	Run(func() int { return 0 })

	if got := os.Getenv("HOME"); got != sentinel {
		t.Errorf("HOME = %q after Run, want the pre-existing value %q", got, sentinel)
	}
	if v, ok := os.LookupEnv("GRANT_CONFIG"); ok {
		t.Errorf("GRANT_CONFIG is set to %q after Run; an originally-unset var must stay unset", v)
	}
}

// Not parallel: mutates process-wide environment variables.
func TestRun_RemovesSandboxRootAfterwards(t *testing.T) {
	var root string
	Run(func() int {
		root = Root()
		if _, err := os.Stat(root); err != nil {
			t.Errorf("sandbox root %q does not exist during run(): %v", root, err)
		}
		return 0
	})

	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("sandbox root %q still exists after Run (stat err = %v)", root, err)
	}
	if Root() != "" {
		t.Errorf("Root() = %q after Run, want empty", Root())
	}
}

// Not parallel: mutates process-wide environment variables.
func TestRun_HomeVarsPointAtARealDirectory(t *testing.T) {
	Run(func() int {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Errorf("os.UserHomeDir() inside sandbox: %v", err)
			return 1
		}
		if !strings.HasPrefix(home, Root()) {
			t.Errorf("os.UserHomeDir() = %q, want a path under sandbox root %q", home, Root())
		}
		info, err := os.Stat(home)
		if err != nil {
			t.Errorf("sandbox home %q not created: %v", home, err)
			return 1
		}
		if !info.IsDir() {
			t.Errorf("sandbox home %q is not a directory", home)
		}
		return 0
	})
}

// Not parallel: mutates process-wide environment variables.
func TestAssertSandboxed_PassesInsideSandbox(t *testing.T) {
	Run(func() int {
		rec := &recordingTB{}
		AssertSandboxed(rec)
		if len(rec.errs) != 0 {
			t.Errorf("AssertSandboxed reported %d failures inside the sandbox: %v", len(rec.errs), rec.errs)
		}
		if rec.helperCalls == 0 {
			t.Error("AssertSandboxed did not call Helper()")
		}
		return 0
	})
}

// Not parallel: mutates process-wide environment variables.
func TestAssertSandboxed_FailsOutsideSandbox(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The resolvers read USERPROFILE (os.UserHomeDir) and HOME (the SDK
		// profile loader) from different variables on Windows; forcing a
		// deterministic "outside" state needs both, and t.Setenv of HOME on
		// Windows has no effect on os.UserHomeDir. Covered on POSIX instead.
		t.Skip("environment-driven resolvers diverge on Windows; covered on POSIX")
	}

	outside := t.TempDir()
	t.Setenv("HOME", outside)
	t.Setenv("GRANT_CONFIG", filepath.Join(outside, "config.yaml"))
	t.Setenv("IDSEC_PROFILES_FOLDER", filepath.Join(outside, "profiles"))

	rec := &recordingTB{}
	AssertSandboxed(rec)
	if len(rec.errs) == 0 {
		t.Error("AssertSandboxed reported no failures while running outside any sandbox")
	}
}

// TestAssertSandboxed_FailsWhenAResolverEscapes is the case that actually
// matters: a sandbox IS active, but one resolver still points at real user
// state. Without this, the outside-the-sandbox test above would be satisfied
// solely by the Root()=="" short-circuit.
//
// Not parallel: mutates process-wide environment variables.
func TestAssertSandboxed_FailsWhenAResolverEscapes(t *testing.T) {
	escapee := t.TempDir() // deliberately NOT under the sandbox root

	Run(func() int {
		// os.Setenv, not t.Setenv: t.Setenv's cleanup fires when the test
		// ends, which is *after* Run has already restored the environment —
		// it would put this bogus value back and leak it into later tests.
		// Run's own restore covers us here.
		//nolint:usetesting // see comment above
		if err := os.Setenv("IDSEC_PROFILES_FOLDER", escapee); err != nil {
			t.Errorf("Setenv: %v", err)
			return 1
		}
		rec := &recordingTB{}
		AssertSandboxed(rec)
		if len(rec.errs) != 1 {
			t.Errorf("AssertSandboxed reported %d failures, want exactly 1 (the escaped profiles folder): %v",
				len(rec.errs), rec.errs)
		}
		return 0
	})
}

// Not parallel: reads no globals, but kept serial with the rest of the file.
func TestAssertUnder(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "sandbox", "root")

	tests := []struct {
		name     string
		got      string
		wantFail bool
	}{
		{name: "root itself", got: root},
		{name: "direct child", got: filepath.Join(root, "home")},
		{name: "deep descendant", got: filepath.Join(root, "home", ".grant", "cache")},
		{name: "unclean but inside", got: filepath.Join(root, "home", "..", "home", "x")},
		{
			// The classic prefix-matching bug: "/sandbox/rootless" shares a
			// string prefix with "/sandbox/root" but is not under it.
			name:     "sibling sharing a string prefix",
			got:      root + "less",
			wantFail: true,
		},
		{name: "unrelated absolute path", got: filepath.Join(string(filepath.Separator), "home", "tim", ".grant"), wantFail: true},
		{name: "parent of root", got: filepath.Dir(root), wantFail: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recordingTB{}
			assertUnder(rec, "resolver()", tt.got, root)
			if gotFail := len(rec.errs) > 0; gotFail != tt.wantFail {
				t.Errorf("assertUnder(%q, %q) failed = %v, want %v", tt.got, root, gotFail, tt.wantFail)
			}
		})
	}
}

// Not parallel: mutates process-wide environment variables.
func TestRun_IsReentrant(t *testing.T) {
	// Sequential calls must each get their own root. Nesting is covered
	// separately by TestRun_NestsWithoutClobberingTheOuterRoot.
	var first, second string
	Run(func() int {
		first = Root()
		return 0
	})
	Run(func() int {
		second = Root()
		return 0
	})
	if first == "" || second == "" {
		t.Fatal("Root() empty in one of the runs")
	}
	if first == second {
		t.Errorf("both runs used the same sandbox root %q; each run must be isolated", first)
	}
}

// TestRun_NestsWithoutClobberingTheOuterRoot pins the save/restore of
// sandboxRoot. Before it, an inner Run cleared the global on the way out and
// the outer run continued with Root() == "", which makes AssertSandboxed report
// "no sandbox is active" even though one is.
//
// Not parallel: mutates process-wide environment variables.
func TestRun_NestsWithoutClobberingTheOuterRoot(t *testing.T) {
	var outer, inner, afterInner string

	Run(func() int {
		outer = Root()
		Run(func() int {
			inner = Root()
			return 0
		})
		afterInner = Root()
		return 0
	})

	if outer == "" || inner == "" {
		t.Fatalf("Root() empty: outer=%q inner=%q", outer, inner)
	}
	if outer == inner {
		t.Errorf("nested Run reused the outer root %q; each run must get its own", outer)
	}
	if afterInner != outer {
		t.Errorf("Root() = %q after the nested Run returned, want the outer root %q", afterInner, outer)
	}
	if Root() != "" {
		t.Errorf("Root() = %q after both runs, want empty", Root())
	}
}

// TestRun_RestoresEnvironmentAfterAPanic pins the deferred cleanup. Without it
// a panic inside run — a -race detection, or any stray panic — skipped both the
// environment restore and the sandbox removal, so the process kept running with
// a redirected HOME pointing at a directory that still existed.
//
// Not parallel: mutates process-wide environment variables.
func TestRun_RestoresEnvironmentAfterAPanic(t *testing.T) {
	const sentinel = "/sentinel-home-value"
	t.Setenv("HOME", sentinel)

	var root string
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected the panic to propagate out of Run")
			}
		}()
		Run(func() int {
			root = Root()
			panic("boom")
		})
	}()

	if got := os.Getenv("HOME"); got != sentinel {
		t.Errorf("HOME = %q after a panicking Run, want the pre-existing value %q", got, sentinel)
	}
	if Root() != "" {
		t.Errorf("Root() = %q after a panicking Run, want empty", Root())
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("sandbox root %q survived a panicking Run (stat err = %v)", root, err)
	}
}
