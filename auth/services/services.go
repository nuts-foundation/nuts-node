package services

import (
	"github.com/nuts-foundation/go-did"
	"net/http"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"

	"github.com/nuts-foundation/nuts-node/auth/contract"
)

// ContractValidator interface must be implemented by contract validators
// deprecated
type ContractValidator interface {
	// ValidateContract validates a signed login contract
	ValidateContract(contract string, format ContractFormat, checkTime *time.Time) (*ContractValidationResult, error)
	// ValidateJwt validates a JWT that contains a signed login contract
	ValidateJwt(contract string, checkTime *time.Time) (*ContractValidationResult, error)
}

// ContractSessionHandler interface must be implemented by ContractSessionHandlers
// deprecated
type ContractSessionHandler interface {
	SessionStatus(session SessionID) (*SessionStatusResult, error)
	StartSession(request interface{}, handler server.SessionHandler) (*irma.Qr, string, error)
}

// OAuthClient is the client interface for the OAuth service
type OAuthClient interface {
	CreateAccessToken(request CreateAccessTokenRequest) (*AccessTokenResult, error)
	CreateJwtBearerToken(request CreateJwtBearerTokenRequest) (*JwtBearerTokenResult, error)
	IntrospectAccessToken(token string) (*NutsAccessToken, error)
	Configure() error
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

// ContractNotary defines the interface to draw up a contract.
type ContractNotary interface {
	// DrawUpContract draws up a contract from a template and returns a Contract which than can be signed by the user.
	DrawUpContract(template contract.Template, orgID did.DID, validFrom time.Time, validDuration time.Duration) (*contract.Contract, error)

	ValidateContract(contractToValidate contract.Contract, orgID did.DID, checkTime time.Time) (bool, error)
}

// ContractClient defines functions for creating and validating verifiable credentials
type ContractClient interface {
	contract.VPVerifier

	// CreateSigningSession creates a signing session for the requested contract and means
	CreateSigningSession(sessionRequest CreateSessionRequest) (contract.SessionPointer, error)

	// SigningSessionStatus returns the status of the current signing session or ErrSessionNotFound is sessionID is unknown
	SigningSessionStatus(sessionID string) (contract.SigningSessionResult, error)

	Configure() error

	// deprecated
	ContractSessionStatus(sessionID string) (*SessionStatusResult, error)
	// deprecated
	ValidateContract(request ValidationRequest) (*ContractValidationResult, error)
	// HandlerFunc returns the Irma server handler func
	// deprecated
	HandlerFunc() http.HandlerFunc
}
