package sca

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

func TestSDKImports_AuthTypes(t *testing.T) {
	// Verify key SDK auth types are importable
	var _ auth.IdsecAuth
	var _ *auth.IdsecISPAuth

	// NewIdsecISPAuth should be callable (we only check it exists)
	ispAuth := auth.NewIdsecISPAuth(false)
	if ispAuth == nil {
		t.Fatal("expected non-nil IdsecISPAuth")
	}
}

func TestSDKImports_ServiceTypes(t *testing.T) {
	// Verify key SDK service types are importable
	var _ services.IdsecService
	var _ *services.IdsecBaseService
}
