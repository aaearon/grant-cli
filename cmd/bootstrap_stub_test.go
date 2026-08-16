package cmd

import (
	"errors"

	sdkauth "github.com/cyberark/idsec-sdk-golang/pkg/auth"
	sdkmodels "github.com/cyberark/idsec-sdk-golang/pkg/models"
)

// This file carries NO build tag on purpose. Both TestMain implementations —
// the default one in main_test.go and the integration one in
// integration_test.go — install the same stub, so the in-process cmd tests
// behave identically under `go test ./cmd` and `go test -tags=integration
// ./cmd`. The integration tests themselves exercise a separate child process
// and are unaffected.

// errTestBootstrapDisabled is returned by the stubbed bootstrapImpl. It is a
// named sentinel rather than an anonymous error so tests can assert on it with
// errors.Is: a bare `wantErr: true` would otherwise be satisfied by an
// accidental bootstrap attempt, hiding the fact that a unit test reached for
// real credentials.
var errTestBootstrapDisabled = errors.New("bootstrapImpl is disabled in unit tests; inject via New...WithDeps instead")

// installBootstrapStub replaces the real profile-load + authenticate path so
// no in-process test can load the developer's SDK profile or unlock the real
// keyring. Call it from TestMain, before m.Run.
func installBootstrapStub() {
	bootstrapImpl = func() (sdkauth.IdsecAuth, *sdkmodels.IdsecProfile, error) {
		return nil, nil, errTestBootstrapDisabled
	}
	resetBootstrapCache()
}
