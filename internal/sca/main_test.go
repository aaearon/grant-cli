package sca

import (
	"os"
	"testing"

	"github.com/aaearon/grant-cli/internal/testenv"
)

// TestMain redirects HOME and friends at a throwaway directory. This package
// drives the *real* service constructors (see retry_policy_test.go), which
// build an SDK client and can therefore reach the SDK's profile and keyring
// resolution; without the sandbox a new test here could read or write the
// developer's real ~/.idsec with no failing signal.
//
// An in-package (not _test) TestMain is safe here: testenv imports
// internal/sca/models, not internal/sca, so there is no import cycle.
func TestMain(m *testing.M) {
	os.Exit(testenv.Run(m.Run))
}

// TestSandboxIsolation pins the redirect: if TestMain ever stops wrapping
// m.Run, this fails instead of the suite silently touching real user state.
//
// Not parallel: reads process-wide environment state.
func TestSandboxIsolation(t *testing.T) {
	testenv.AssertSandboxed(t)
}
