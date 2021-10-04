package services

import (
	"encoding/json"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"

	irma "github.com/privacybydesign/irmago"
)

// CreateSessionRequest is used to create a contract signing session.
type CreateSessionRequest struct {
	SigningMeans contract.SigningMeans
	// Message to sign
	Message string
}

// CreateSessionResult contains the results needed to setup an irma flow
type CreateSessionResult struct {
	QrCodeInfo irma.Qr
	SessionID  string
}

// CreateAccessTokenRequest contains all information to create an access token from a JwtBearerToken
type CreateAccessTokenRequest struct {
	RawJwtBearerToken string
}

// CreateJwtGrantRequest contains all information to create a JwtBearerToken
type CreateJwtGrantRequest struct {
	Requester     string
	Authorizer    string
	IdentityToken *string
	Service       string
	Subject       *string
	Credentials   []vc.VerifiableCredential
}

// AccessTokenResult defines the return value back to the api for the CreateAccessToken method
type AccessTokenResult struct {
	AccessToken string
}

// JwtBearerTokenResult defines the return value back to the api for the createJwtBearerToken method
type JwtBearerTokenResult struct {
	BearerToken string
}

// NutsAccessToken is a OAuth 2.0 access token which provides context to a request.
// Its contents are derived from a Jwt Bearer token. The Jwt Bearer token is verified by the authorization server and
// stripped from the proof to make it compact.
type NutsAccessToken struct {
	SubjectID  *string `json:"sid,omitempty"`
	Service    string  `json:"service"`
	Name       *string `json:"name,omitempty"`
	GivenName  *string `json:"given_name,omitempty"`
	Prefix     *string `json:"prefix,omitempty"`
	FamilyName *string `json:"family_name,omitempty"`
	Email      *string `json:"email,omitempty"`

	KeyID       string   `json:"-"`
	Expiration  int64    `json:"exp"`
	IssuedAt    int64    `json:"iat"`
	Issuer      string   `json:"iss"`
	Subject     string   `json:"sub"`
	Audience    string   `json:"aud"`
	Credentials []string `json:"vcs,omitempty"`
}

// FromMap sets the values of the token from the given map.
func (t *NutsAccessToken) FromMap(m map[string]interface{}) error {
	data, _ := json.Marshal(m)
	return json.Unmarshal(data, t)
}

// ContractValidationResult contains the result of a contract validation
type ContractValidationResult struct {
	ValidationResult ValidationState `json:"validation_result"`
	ContractFormat   ContractFormat  `json:"contract_format"`
	// DisclosedAttributes contain the attributes used to sign this contract
	DisclosedAttributes map[string]string `json:"disclosed_attributes"`
	// ContractAttributes contain the attributes used to fill the contract
	ContractAttributes map[string]string `json:"contract_attributes"`
}
