package auth

import (
	"github.com/nuts-foundation/nuts-node/auth/services"
)

// AuthenticationServices is the interface which should be implemented for clients or mocks
type AuthenticationServices interface {
	// OAuthClient returns an instance of OAuthClient
	OAuthClient() services.OAuthClient
	// ContractClient returns an instance of ContractClient
	ContractClient() services.ContractClient
	// ContractNotary returns an instance of ContractNotary
	ContractNotary() services.ContractNotary
}
