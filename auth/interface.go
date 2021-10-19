package auth

import (
	"crypto/tls"
	"crypto/x509"
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
	// TrustStore contains an certificate pool (only when TLS is enabled)
	TrustStore() *x509.CertPool
	// ClientCertificate returns a tls.Certificate (only when TLS is enabled)
	ClientCertificate() *tls.Certificate
	// TLSEnabled returns true if TLS is enabled (mTLS)
	TLSEnabled() bool
}
