package services

import (
	"encoding/json"
	"errors"
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

// SessionID contains a number to uniquely identify a contract signing session
type SessionID string

// ValidationState contains the outcome of the validation. It van be VALID or INVALID. This makes it human readable.
type ValidationState string

// ContractFormat describes the format of a signed contract. Based on the format an appropriate validator can be selected.
type ContractFormat string

// OAuthEndpointType defines the type identifier for oauth endpoints (RFCtodo)
const OAuthEndpointType = "oauth"
