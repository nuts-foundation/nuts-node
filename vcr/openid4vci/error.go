/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package openid4vci

// ErrorCode specifies error codes as defined by the OpenID4VCI spec.
type ErrorCode string

const (
	// OAuth2 Token Endpoint error codes (RFC 6749)

	// InvalidRequest is an OAuth2 error for malformed token requests.
	InvalidRequest ErrorCode = "invalid_request"
	// InvalidClient is returned when the client is not authorized.
	InvalidClient ErrorCode = "invalid_client"
	// InvalidGrant is returned when the grant (e.g. pre-authorized code) is invalid or expired.
	InvalidGrant ErrorCode = "invalid_grant"
	// InvalidToken is returned when the access token is invalid or missing (RFC 6750).
	InvalidToken ErrorCode = "invalid_token"
	// UnsupportedGrantType is returned when the requested grant type is not supported.
	UnsupportedGrantType ErrorCode = "unsupported_grant_type"
	// ServerError is returned when the server encounters an unexpected condition.
	ServerError ErrorCode = "server_error"

	// OpenID4VCI v1.0 Credential Endpoint error codes (Section 8.3.1.2)

	// InvalidCredentialRequest is returned when the Credential Request is missing a required parameter,
	// includes an unsupported parameter or parameter value, or is otherwise malformed.
	InvalidCredentialRequest ErrorCode = "invalid_credential_request"
	// UnknownCredentialConfiguration is returned when the requested credential_configuration_id is unknown.
	UnknownCredentialConfiguration ErrorCode = "unknown_credential_configuration"
	// UnknownCredentialIdentifier is returned when the requested credential_identifier is unknown.
	UnknownCredentialIdentifier ErrorCode = "unknown_credential_identifier"
	// InvalidProof is returned when the proofs parameter is invalid: missing, one of the key proofs
	// is invalid, or a key proof does not contain a c_nonce value.
	InvalidProof ErrorCode = "invalid_proof"
	// InvalidNonce is returned when at least one of the key proofs contains an invalid c_nonce value.
	// The wallet should retrieve a new c_nonce value from the Nonce Endpoint (Section 7).
	InvalidNonce ErrorCode = "invalid_nonce"
	// InvalidEncryptionParameters is returned when the encryption parameters in the Credential Request
	// are either invalid or missing when the issuer requires encrypted responses.
	InvalidEncryptionParameters ErrorCode = "invalid_encryption_parameters"
	// CredentialRequestDenied is returned when the Credential Request has not been accepted by the
	// issuer. The wallet SHOULD treat this as unrecoverable.
	CredentialRequestDenied ErrorCode = "credential_request_denied"
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
