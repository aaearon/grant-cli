package workflows

import "github.com/cyberark/idsec-sdk-golang/pkg/services"

// ServiceConfig returns the configuration for the Access Requests Service.
// It specifies the service name "access-requests" and requires the "isp" authenticator.
func ServiceConfig() services.IdsecServiceConfig {
	return services.IdsecServiceConfig{
		ServiceName:                "access-requests",
		RequiredAuthenticatorNames: []string{"isp"},
		OptionalAuthenticatorNames: []string{},
		ActionsConfigurations:      nil,
	}
}
