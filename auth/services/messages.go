package services

import (
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/auth/contract"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
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

// SessionStatusResult contains the current state of a session. If the session is DONE it also contains a JWT in the NutsAuthToken
// deprecated
type SessionStatusResult struct {
	server.SessionResult
	// NutsAuthToken contains the JWT if the sessionStatus is DONE
	NutsAuthToken string `json:"nuts_auth_token"`
}

// ValidationRequest is used to pass all information to ValidateContract
// deprecated, moved to pkg/contract
type ValidationRequest struct {
	// ContractFormat specifies the type of format used for the contract, e.g. 'irma'
	ContractFormat ContractFormat

	// The actual contract in string format to validate
	ContractString string
}

// CreateAccessTokenRequest contains all information to create an access token from a JwtBearerToken
type CreateAccessTokenRequest struct {
	RawJwtBearerToken string
}

// CreateJwtBearerTokenRequest contains all information to create a JwtBearerToken
type CreateJwtBearerTokenRequest struct {
	Actor         string
	Custodian     string
	IdentityToken *string
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

// NutsJwtBearerToken contains the deserialized Jwt Bearer Token as defined in rfc7523. It contains a NutsIdentity token which can be
// verified by the authorization server.
type NutsJwtBearerToken struct {
	// Base64 encoded VerifiablePresentation
	UserIdentity *string `json:"usi,omitempty"`
	SubjectID    *string `json:"sid,omitempty"`
	Scope        string  `json:"scope"`
	KeyID        string  `json:"kid"`
}

// NutsAccessToken is a OAuth 2.0 access token which provides context to a request.
// Its contents are derived from a Jwt Bearer token. The Jwt Bearer token is verified by the authorization server and
// stripped from the proof to make it compact.
type NutsAccessToken struct {
	SubjectID  *string `json:"sid"`
	Scope      string  `json:"scope"`
	Name       string  `json:"name"`
	GivenName  string  `json:"given_name"`
	Prefix     string  `json:"prefix"`
	FamilyName string  `json:"family_name"`
	Email      string  `json:"email"`

	KeyID      string `json:"kid"`
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
// deprecated, moved to pkg/contract
type ContractValidationResult struct {
	ValidationResult ValidationState `json:"validation_result"`
	ContractFormat   ContractFormat  `json:"contract_format"`
	// DisclosedAttributes contain the attributes used to sign this contract
	DisclosedAttributes map[string]string `json:"disclosed_attributes"`
	// ContractAttributes contain the attributes used to fill the contract
	ContractAttributes map[string]string `json:"contract_attributes"`
}
