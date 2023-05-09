package oidc4vci

// ErrorCode specifies error codes as defined by the OpenID4VCI spec.
type ErrorCode string

const (
	// InvalidRequest is returned when:
	// - the Authorization Server does not expect a PIN in the pre-authorized flow but the client provides a PIN
	// - the Authorization Server expects a PIN in the pre-authorized flow but the client does not provide a PIN
	// - Credential Request was malformed. One or more of the parameters (i.e. format, proof) are missing or malformed.
	InvalidRequest ErrorCode = "invalid_request"
	// InvalidClient is returned when:
	// - the client tried to send a Token Request with a Pre-Authorized Code without Client ID but the Authorization Server does not support anonymous access
	InvalidClient ErrorCode = "invalid_client"
	// InvalidGrant is returned when (in addition to cases defined by OAuth2):
	// - the Authorization Server expects a PIN in the pre-authorized flow but the client provides the wrong PIN
	// - the End-User provides the wrong Pre-Authorized Code or the Pre-Authorized Code has expired
	InvalidGrant ErrorCode = "invalid_grant"
	// InvalidToken is returned when (in addition to cases defined by OAuth2):
	// - Credential Request contains the wrong Access Token or the Access Token is missing
	InvalidToken ErrorCode = "invalid_token"
	// UnsupportedGrantType is returned when the Authorization Server does not support the requested grant type.
	UnsupportedGrantType ErrorCode = "unsupported_grant_type"
	// ServerError is returned when the Authorization Server encounters an unexpected condition that prevents it from fulfilling the request.
	ServerError ErrorCode = "server_error"
	// UnsupportedCredentialType is returned when the credential issuer does not support the requested credential type.
	UnsupportedCredentialType ErrorCode = "unsupported_credential_type"
	// UnsupportedCredentialFormat is returned when the credential issuer does not support the requested credential format.
	UnsupportedCredentialFormat ErrorCode = "unsupported_credential_format"
	// InvalidOrMissingProof is returned when the Credential Request did not contain a proof,
	// or proof was invalid, i.e. it was not bound to a Credential Issuer provided nonce
	InvalidOrMissingProof ErrorCode = "invalid_or_missing_proof"
)

// Error is an error that signals the error was (probably) caused by the client (e.g. bad request),
// or that the client can recover from the error (e.g. retry). Errors are specified by the OpenID4VCI specification.
type Error struct {
	// Code is the error code as defined by the OpenID4VCI spec.
	Code ErrorCode `json:"error"`
	// Err is the underlying error, may be omitted. It is not intended to be returned to the client.
	Err error `json:"-"`
	// StatusCode is the HTTP status code that should be returned to the client.
	StatusCode int `json:"-"`
}

// Error returns the error message, which is either the underlying error or the code if there is no underlying error
func (e Error) Error() string {
	if e.Err == nil {
		return string(e.Code)
	}
	return string(e.Code) + " - " + e.Err.Error()
}
