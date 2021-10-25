package auth

import (
	"crypto/tls"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/services"
)

// AuthenticationServices is the interface which should be implemented for clients or mocks
type AuthenticationServices interface {
	// OAuthClient returns an instance of OAuthClient
	OAuthClient() services.OAuthClient
	// ContractNotary returns an instance of ContractNotary
	ContractNotary() services.ContractNotary
	// HTTPTimeout returns the HTTP timeout to use for the Auth API HTTP client
	HTTPTimeout() time.Duration
	// TLSConfig returns the TLS configuration when TLS is enabled and nil if it's disabled
	TLSConfig() *tls.Config
}
