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
	"errors"
	"fmt"
)

const (
	// IrmaFormat is used to indicate a contract is in he form of a base64 encoded IRMA signature
	IrmaFormat ContractFormat = "irma"
	// Valid is used to indicate a contract was valid on the time of testing
	Valid ValidationState = "VALID"
	// Invalid is used to indicate a contract was invalid on the time of testing
	Invalid ValidationState = "INVALID"
)

// NutsIdentityToken contains the signed identity of the user performing the request
type NutsIdentityToken struct {
	// KeyID identifies the key that was used to sign the token
	KeyID string `json:"kid"`
	// What kind of signature? Currently only IRMA is supported
	Type ContractFormat `json:"type"`
	// The base64 encoded signature
	Signature string `json:"sig"`
}

// FromMap sets the values of the token from the given map.
func (t *NutsIdentityToken) FromMap(m map[string]interface{}) error {
	data, _ := json.Marshal(m)
	return json.Unmarshal(data, t)
}

// ErrSessionNotFound is returned when there is no contract signing session found for a certain SessionID
var ErrSessionNotFound = errors.New("session not found")

// InvalidContractRequestError is returned when the contract request is invalid
type InvalidContractRequestError struct {
	message interface{}
}

func NewInvalidContractRequestError(msg interface{}) InvalidContractRequestError {
	return InvalidContractRequestError{msg}
}

func (e InvalidContractRequestError) Error() string {
	return fmt.Sprintf("could not draw up contract: %v", e.message)
}

func (e InvalidContractRequestError) Is(target error) bool {
	_, ok := target.(InvalidContractRequestError)
	return ok
}

// SessionID contains a number to uniquely identify a contract signing session
type SessionID string

// ValidationState contains the outcome of the validation. It van be VALID or INVALID. This makes it human readable.
type ValidationState string

// ContractFormat describes the format of a signed contract. Based on the format an appropriate validator can be selected.
type ContractFormat string

// OAuthEndpointType defines the type identifier for oauth endpoints (RFCtodo)
const OAuthEndpointType = "oauth"

// InitialsTokenClaim is the JWT claim for initials
const InitialsTokenClaim = "initials"

// FamilyNameTokenClaim is the JWT claim for the family name
const FamilyNameTokenClaim = "familyname"

// PrefixTokenClaim is the JWT claim for the name prefix
const PrefixTokenClaim = "prefix"

// EmailTokenClaim is the JWT claim for email
const EmailTokenClaim = "email"

// EidasIALClaim is the EIDAS identity assurance level claim: Low - to - High
const EidasIALClaim = "eidas_ial"

// UsernameClaim is the JWT claim for the username. This may be an identifier or email depending on the means used.
// The claim is a default claim according toRFC 7662 (https://www.rfc-editor.org/rfc/rfc7662)
const UsernameClaim = "username"
