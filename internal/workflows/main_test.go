package workflows

import (
	"os"
	"testing"

	"github.com/aaearon/grant-cli/internal/testenv"
)

// TestMain redirects HOME and friends at a throwaway directory. This package
// drives the *real* AccessRequestService constructor (see retry_policy_test.go),
// which builds an SDK client and can therefore reach the SDK's profile and
// keyring resolution; without the sandbox a new test here could read or write
// the developer's real ~/.idsec with no failing signal.
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
