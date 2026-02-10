package sca

import "github.com/cyberark/idsec-sdk-golang/pkg/services"

// ServiceConfig returns the configuration for the SCA Access Service.
// It specifies the service name "sca-access" and requires the "isp" authenticator.
func ServiceConfig() services.IdsecServiceConfig {
	return services.IdsecServiceConfig{
		ServiceName:                "sca-access",
		RequiredAuthenticatorNames: []string{"isp"},
		OptionalAuthenticatorNames: []string{},
		ActionsConfigurations:      nil,
	}
}
