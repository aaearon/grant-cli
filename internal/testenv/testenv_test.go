package testenv

import (
	"os"
	"path/filepath"
	"runtime"
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

// Not parallel: mutates process-wide environment variables.
func TestRun_RedirectsAllHomeEnvVars(t *testing.T) {
	var (
		gotRoot string
		seen    = map[string]string{}
	)

	code := Run(func() int {
		gotRoot = Root()
		for _, k := range redirectedVars {
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

	for _, k := range redirectedVars {
		v := seen[k]
		if v == "" {
			t.Errorf("%s was empty inside run(); every redirected var must be set", k)
			continue
		}
		if !strings.HasPrefix(v, gotRoot) {
			t.Errorf("%s = %q, want a path under the sandbox root %q", k, v, gotRoot)
		}
	}
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
	// Nested/sequential calls must each get their own root and leave the
	// process environment as they found it.
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
