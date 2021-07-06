package services

import (
	"encoding/json"

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
	Actor         string
	Custodian     string
	IdentityToken *string
	Service       string
	Subject       *string
}

// AccessTokenResult defines the return value back to the api for the CreateAccessToken method
type AccessTokenResult struct {
	AccessToken string
}

// JwtBearerTokenResult defines the return value back to the api for the createJwtBearerToken method
type JwtBearerTokenResult struct {
	BearerToken string
}

// JWTService is the field used to denote the selected service in the JWT
const JWTService = "service"

// NutsJwtBearerToken contains the deserialized Jwt Bearer Token as defined in rfc7523. It contains a NutsIdentity token which can be
// verified by the authorization server.
type NutsJwtBearerToken struct {
	// Base64 encoded VerifiablePresentation
	UserIdentity *string `json:"usi,omitempty"`
	SubjectID    *string `json:"sid,omitempty"`
	// Service defines the use-case for which an access token is required
	Service string `json:"service"`
	KeyID   string `json:"-"`
}

// NutsAccessToken is a OAuth 2.0 access token which provides context to a request.
// Its contents are derived from a Jwt Bearer token. The Jwt Bearer token is verified by the authorization server and
// stripped from the proof to make it compact.
type NutsAccessToken struct {
	SubjectID  *string `json:"sid"`
	Service    string  `json:"service"`
	Name       string  `json:"name"`
	GivenName  string  `json:"given_name"`
	Prefix     string  `json:"prefix"`
	FamilyName string  `json:"family_name"`
	Email      string  `json:"email"`

	KeyID      string `json:"-"`
	Expiration int64  `json:"exp"`
	IssuedAt   int64  `json:"iat"`
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	Audience   string `json:"aud"`
}

// FromMap sets the values of the token from the given map.
func (t *NutsAccessToken) FromMap(m map[string]interface{}) error {
	data, _ := json.Marshal(m)
	return json.Unmarshal(data, t)
}

// AsMap returns the claims from a NutsJwtBearerToken as a map with the json names as keys
func (token NutsJwtBearerToken) AsMap() (map[string]interface{}, error) {
	var keyVals map[string]interface{}
	inrec, _ := json.Marshal(token)
	if err := json.Unmarshal(inrec, &keyVals); err != nil {
		return nil, err
	}
	return keyVals, nil
}

// FromMap sets the values of the token from the given map.
func (token *NutsJwtBearerToken) FromMap(m map[string]interface{}) error {
	data, _ := json.Marshal(m)
	return json.Unmarshal(data, token)
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
