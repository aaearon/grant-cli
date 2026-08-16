// This file is in the external test package (cache_test) on purpose: the
// testenv helper imports internal/cache, so an in-package test file importing
// testenv would be an import cycle. TestMain may live in either test package
// and still governs the whole test binary.
package cache_test

import (
	"os"
	"testing"

	"github.com/aaearon/grant-cli/internal/testenv"
)

// TestMain redirects HOME and friends at a throwaway directory so tests in this
// package can never touch the developer's real ~/.grant cache.
func TestMain(m *testing.M) {
	os.Exit(testenv.Run(m.Run))
}

// TestSandboxIsolation pins the redirect: if TestMain ever stops wrapping
// m.Run, or a resolver starts reading a variable testenv does not override,
// this fails instead of silently writing to the developer's home directory.
//
// Not parallel: reads process-wide environment state.
func TestSandboxIsolation(t *testing.T) {
	testenv.AssertSandboxed(t)
}
