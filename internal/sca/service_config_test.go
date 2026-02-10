package sca

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

func TestServiceConfig_ServiceName(t *testing.T) {
	config := ServiceConfig()
	expected := "sca-access"
	if config.ServiceName != expected {
		t.Errorf("expected ServiceName %q, got %q", expected, config.ServiceName)
	}
}

func TestServiceConfig_RequiredAuthenticators(t *testing.T) {
	config := ServiceConfig()
	if len(config.RequiredAuthenticatorNames) != 1 {
		t.Fatalf("expected 1 required authenticator, got %d", len(config.RequiredAuthenticatorNames))
	}
	expected := "isp"
	if config.RequiredAuthenticatorNames[0] != expected {
		t.Errorf("expected required authenticator %q, got %q", expected, config.RequiredAuthenticatorNames[0])
	}
}

func TestServiceConfig_OptionalAuthenticators(t *testing.T) {
	config := ServiceConfig()
	if len(config.OptionalAuthenticatorNames) != 0 {
		t.Errorf("expected 0 optional authenticators, got %d", len(config.OptionalAuthenticatorNames))
	}
}

func TestServiceConfig_ActionsConfigurations(t *testing.T) {
	config := ServiceConfig()
	if config.ActionsConfigurations != nil {
		t.Errorf("expected nil ActionsConfigurations, got %v", config.ActionsConfigurations)
	}
}

func TestServiceConfig_ReturnsIdsecServiceConfig(t *testing.T) {
	config := ServiceConfig()
	// Verify it returns the correct SDK type
	var _ services.IdsecServiceConfig = config
}
