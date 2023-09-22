/*
 * Copyright (C) 2021 Nuts community
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

package services

import (
	"encoding/json"

	"github.com/nuts-foundation/go-did/vc"
	irma "github.com/privacybydesign/irmago"
)

// CreateSessionRequest is used to create a contract signing session.
type CreateSessionRequest struct {
	SigningMeans string
	// Message to sign
	Message string
	// Params contain means specific parameters
	Params map[string]interface{}
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
	Requester   string
	Authorizer  string
	IdentityVP  *vc.VerifiablePresentation
	Service     string
	Credentials []vc.VerifiableCredential
}

// JwtBearerTokenResult defines the return value back to the api for the createJwtBearerToken method
type JwtBearerTokenResult struct {
	BearerToken                 string
	AuthorizationServerEndpoint string
}

// NutsAccessToken is a OAuth 2.0 access token which provides context to a request.
// Its contents are derived from a Jwt Bearer token. The Jwt Bearer token is verified by the authorization server and
// stripped from the proof to make it compact.
type NutsAccessToken struct {
	Service        string  `json:"service"`
	Initials       *string `json:"initials,omitempty"`
	Prefix         *string `json:"prefix,omitempty"`
	FamilyName     *string `json:"family_name,omitempty"`
	Email          *string `json:"email,omitempty"`
	AssuranceLevel *string `json:"assurance_level,omitempty"`
	Username       *string `json:"username,omitempty"`
	UserRole       *string `json:"user_role,omitempty"`

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
	FailureReason    string          `json:"failure_reason"`
	ContractFormat   ContractFormat  `json:"contract_format"`
	// DisclosedAttributes contain the attributes used to sign this contract
	DisclosedAttributes map[string]string `json:"disclosed_attributes"`
	// ContractAttributes contain the attributes used to fill the contract
	ContractAttributes map[string]string `json:"contract_attributes"`
}
