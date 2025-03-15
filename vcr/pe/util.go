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

package pe

import (
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/json"
)

// Envelope is a parsed Presentation Exchange envelope, containing zero or more Verifiable Presentations that are referenced by the Presentation Submission.
type Envelope struct {
	// Presentations contains the Verifiable Presentations that were parsed from the envelope.
	Presentations []vc.VerifiablePresentation
	asInterface   interface{}
	raw           []byte
}

func (e *Envelope) UnmarshalJSON(bytes []byte) error {
	var raw interface{}
	if err := json.Unmarshal(bytes, &raw); err != nil {
		return err
	}
	if asString, isJSONString := raw.(string); isJSONString {
		bytes = []byte(asString)
	}
	envelope, err := ParseEnvelope(bytes)
	if err != nil {
		return err
	}
	*e = *envelope
	return nil
}

func (e Envelope) MarshalJSON() ([]byte, error) {
	// If raw is a JSON Array or JSON Object, return as is. Otherwise, marshal convert to string first, then marshal.
	if e.raw[0] == '[' || e.raw[0] == '{' {
		return e.raw, nil
	}
	return json.Marshal(string(e.raw))
}

var _ json.Unmarshaler = &Envelope{}
var _ json.Marshaler = Envelope{}

// ParseEnvelope parses a Presentation Exchange envelope, which is a JSON type that encompasses zero or more Verifiable Presentations.
// It returns the envelope as interface{} for use in PresentationSubmission.Validate() and PresentationSubmission.Resolve().
// It also returns the parsed Verifiable Presentations.
// Parsing is complicated since a Presentation Submission has multiple ways to reference a Verifiable Credential:
// - single VP as JSON object: $.verifiableCredential
// - multiple VPs as JSON array (with path_nested): $[0] -> $.verifiableCredential
// And since JWT VPs aren't JSON objects, we need to parse them separately.
func ParseEnvelope(envelopeBytes []byte) (*Envelope, error) {
	jsonArray := tryParseJSONArray(envelopeBytes)
	if jsonArray != nil {
		// Array of Verifiable Presentations
		asInterface, presentations, err := parseJSONArrayEnvelope(jsonArray)
		if err != nil {
			return nil, err
		}
		return &Envelope{
			asInterface:   asInterface,
			Presentations: presentations,
			raw:           envelopeBytes,
		}, nil
	}
	// Single Verifiable Presentation
	asInterface, presentation, err := parseJSONObjectOrStringEnvelope(envelopeBytes)
	if err != nil {
		return nil, err
	}
	return &Envelope{
		asInterface:   asInterface,
		Presentations: []vc.VerifiablePresentation{*presentation},
		raw:           envelopeBytes,
	}, nil
}

// parseEnvelopeEntry parses a single Verifiable Presentation in a Presentation Exchange envelope.
// It takes into account custom unmarshalling required for JWT VPs.
func parseJSONArrayEnvelope(arr []interface{}) (interface{}, []vc.VerifiablePresentation, error) {
	var presentations []vc.VerifiablePresentation
	var asInterfaces []interface{}
	for _, entry := range arr {
		// Each entry can be a VP as JWT (string) or JSON (object)
		var entryBytes []byte
		switch typedEntry := entry.(type) {
		case string:
			// JWT
			entryBytes = []byte(typedEntry)
		default:
			var err error
			entryBytes, err = json.Marshal(entry)
			if err != nil {
				return nil, nil, err
			}
		}
		asInterface, presentation, err := parseJSONObjectOrStringEnvelope(entryBytes)
		if err != nil {
			return nil, nil, err
		}
		asInterfaces = append(asInterfaces, asInterface)
		presentations = append(presentations, *presentation)
	}
	return asInterfaces, presentations, nil
}

// parseJSONObjectOrStringEnvelope parses a single Verifiable Presentation in a Presentation Exchange envelope.
// It takes into account custom unmarshalling required for JWT VPs (since they're JSON strings, not objects).
func parseJSONObjectOrStringEnvelope(envelopeBytes []byte) (interface{}, *vc.VerifiablePresentation, error) {
	presentation, err := vc.ParseVerifiablePresentation(string(envelopeBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse PEX envelope as verifiable presentation: %w", err)
	}
	// TODO: This should be part of go-did library; we need to decode a JWT VP (and maybe later VC) and get the properties
	//       (in this case as map) without losing original cardinality.
	//       Part of https://github.com/nuts-foundation/go-did/issues/85
	if presentation.Format() == vc.JWTPresentationProofFormat {
		token, err := jwt.Parse(envelopeBytes, jwt.WithVerify(false), jwt.WithValidate(false))
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse PEX envelope as JWT verifiable presentation: %w", err)
		}
		asMap := make(map[string]interface{})
		// use the 'vp' claim as base Verifiable Presentation properties
		innerVPAsMap, _ := token.PrivateClaims()["vp"].(map[string]interface{})
		for key, value := range innerVPAsMap {
			asMap[key] = value
		}
		if jti, ok := token.Get(jwt.JwtIDKey); ok {
			asMap["id"] = jti
		}
		return asMap, presentation, nil
	}
	// For other formats, we can just parse the JSON to get the interface{} for JSON Path to work on
	var asMap interface{}
	if err := json.Unmarshal(envelopeBytes, &asMap); err != nil {
		// Can't actually fail?
		return nil, nil, err
	}
	return asMap, presentation, nil
}

// tryParseJSONArray tries to parse the given bytes as a JSON array.
// It returns the array as []interface{} if the bytes are a JSON array, or nil otherwise.
func tryParseJSONArray(bytes []byte) []interface{} {
	var asInterface interface{}
	if err := json.Unmarshal(bytes, &asInterface); err != nil {
		return nil
	}
	arr, _ := asInterface.([]interface{})
	return arr
}
