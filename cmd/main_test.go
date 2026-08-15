//go:build !integration

// The build tag is load-bearing: cmd/integration_test.go declares its own
// TestMain under `//go:build integration`, and two TestMain symbols in one
// package will not compile. Both harnesses call testenv.Run.
package cmd

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/cache"
	"github.com/aaearon/grant-cli/internal/testenv"
	sdkauth "github.com/cyberark/idsec-sdk-golang/pkg/auth"
	sdkmodels "github.com/cyberark/idsec-sdk-golang/pkg/models"
)

// errTestBootstrapDisabled is returned by the stubbed bootstrapImpl. It is a
// named sentinel rather than an anonymous error so tests can assert on it with
// errors.Is: a bare `wantErr: true` would otherwise be satisfied by an
// accidental bootstrap attempt, hiding the fact that a unit test reached for
// real credentials.
var errTestBootstrapDisabled = errors.New("bootstrapImpl is disabled in unit tests; inject via New...WithDeps instead")

// TestMain does two things, in this order:
//
//  1. Redirects HOME/USERPROFILE/XDG_CONFIG_HOME/IDSEC_PROFILES_FOLDER/
//     GRANT_CONFIG at a throwaway directory. Before this existed the suite
//     wrote the developer's real ~/.grant/cache/session_timestamps.json on
//     every run, because cache.CacheDir resolves through os.UserHomeDir and
//     GRANT_CONFIG does not affect it.
//  2. Replaces bootstrapImpl, so no unit test can load the real SDK profile
//     or unlock the real keyring.
//
// recordSessionTimestamp is deliberately NOT stubbed: leaving the real writer
// live is what proves the HOME redirect actually works.
func TestMain(m *testing.M) {
	os.Exit(testenv.Run(func() int {
		bootstrapImpl = func() (sdkauth.IdsecAuth, *sdkmodels.IdsecProfile, error) {
			return nil, nil, errTestBootstrapDisabled
		}
		resetBootstrapCache()
		return m.Run()
	}))
}

// TestSandboxIsolation pins the redirect. If TestMain ever stops wrapping
// m.Run, this fails instead of the suite silently writing to the real home.
//
// Not parallel: reads process-wide environment state.
func TestSandboxIsolation(t *testing.T) {
	testenv.AssertSandboxed(t)
}

// TestCacheDirResolvesInsideSandbox is the specific regression for the 25
// writes to the developer's real ~/.grant/cache/session_timestamps.json. The
// chain is recordSessionTimestamp -> cache.CacheDir -> config.ConfigDir ->
// os.UserHomeDir, which GRANT_CONFIG does not influence at all.
//
// Not parallel: reads process-wide environment state.
func TestCacheDirResolvesInsideSandbox(t *testing.T) {
	dir, err := cache.CacheDir()
	if err != nil {
		t.Fatalf("cache.CacheDir(): %v", err)
	}
	root := testenv.Root()
	if root == "" {
		t.Fatal("no testenv sandbox is active; TestMain is not wrapping m.Run")
	}
	if !strings.HasPrefix(dir, root) {
		t.Errorf("cache.CacheDir() = %q, want a path under the sandbox root %q", dir, root)
	}
}

// TestBootstrapSCAServiceIsDisabledInUnitTests asserts the sentinel
// specifically. Asserting merely "some error" would let a cached bootstrap
// failure satisfy unrelated wantErr cases in other tables.
//
// Not parallel: mutates the package-global bootstrap memoization state.
func TestBootstrapSCAServiceIsDisabledInUnitTests(t *testing.T) {
	resetBootstrapCache()
	t.Cleanup(resetBootstrapCache)

	_, _, _, err := bootstrapSCAService()
	if !errors.Is(err, errTestBootstrapDisabled) {
		t.Fatalf("bootstrapSCAService() error = %v, want errTestBootstrapDisabled", err)
	}
}
