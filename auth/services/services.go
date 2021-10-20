package services

import (
	"net/http"
	"net/url"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/contract"
)

// OAuthClient is the client interface for the OAuth service
type OAuthClient interface {
	Configure(clockSkew int) error
	CreateAccessToken(request CreateAccessTokenRequest) (*AccessTokenResult, error)
	CreateJwtGrant(request CreateJwtGrantRequest) (*JwtBearerTokenResult, error)
	GetOAuthEndpointURL(service string, authorizer did.DID) (url.URL, error)
	IntrospectAccessToken(token string) (*NutsAccessToken, error)
}

// SignedToken defines the uniform interface to crypto specific implementations such as Irma or x509 tokens.
type SignedToken interface {
	// SignerAttributes extracts a map of attribute names and their values from the signature
	SignerAttributes() (map[string]string, error)
	// Contract extracts the Contract from the SignedToken
	Contract() contract.Contract
}

// VPProofValueParser provides a uniform interface for Authentication services like IRMA or x509 signed tokens
type VPProofValueParser interface {
	// Parse accepts a raw ProofValue from the VP as a string. The parser tries to parse the value into a SignedToken.
	Parse(rawAuthToken string) (SignedToken, error)

	// Verify accepts a SignedToken and verifies the signature using the crypto for the specific implementation of this interface.
	Verify(token SignedToken) error
}

// ContractNotary defines the functions for creating, validating verifiable credentials and draw up a contract.
type ContractNotary interface {
	contract.VPVerifier

	// DrawUpContract draws up a contract from a template and returns a Contract which than can be signed by the user.
	DrawUpContract(template contract.Template, orgID did.DID, validFrom time.Time, validDuration time.Duration) (*contract.Contract, error)

	// CreateSigningSession creates a signing session for the requested contract and means
	CreateSigningSession(sessionRequest CreateSessionRequest) (contract.SessionPointer, error)

	// SigningSessionStatus returns the status of the current signing session or ErrSessionNotFound is sessionID is unknown
	SigningSessionStatus(sessionID string) (contract.SigningSessionResult, error)

	Configure() error

	// HandlerFunc returns the Irma server handler func
	HandlerFunc() http.HandlerFunc
}

// CompoundServiceClient defines a function to get a compoundservice by its servicetype
type CompoundServiceClient interface {
	GetCompoundService(id did.DID, serviceType string) (*did.Service, error)
}
