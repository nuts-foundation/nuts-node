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

package types

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func Test_CompactingVerifiableCredential_Marshalling(t *testing.T) {
	r := CompactingVerifiableCredential{
		Context: []ssi.URI{
			ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
		},
		Type: []ssi.URI{
			ssi.MustParseURI("VerifiableCredential"),
		},
		CredentialSubject: []interface{}{
			map[string]interface{}{
				"id": "did:nuts:123",
			},
		},
		Proof: []interface{}{
			map[string]interface{}{
				"type": "Ed25519Signature2018",
			},
		},
	}
	data, _ := json.Marshal(r)
	result := make(map[string]interface{}, 0)
	err := json.Unmarshal(data, &result)
	require.NoError(t, err)

	// single entries should not end up as slice
	assert.IsType(t, make(map[string]interface{}), result["credentialSubject"])
	assert.IsType(t, make(map[string]interface{}), result["proof"])
	assert.IsType(t, "", result["@context"])
	assert.IsType(t, "", result["type"])
}

func Test_CompactingVerifiablePresentation_MarshalJSON(t *testing.T) {
	issuanceDate := time.Now()
	r := CompactingVerifiablePresentation{
		Context: []ssi.URI{
			ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
		},
		Type: []ssi.URI{
			ssi.MustParseURI("VerifiablePresentation"),
		},
		VerifiableCredential: []vc.VerifiableCredential{
			{
				IssuanceDate: &issuanceDate,
			},
		},
		Proof: []interface{}{
			map[string]interface{}{
				"type": "Ed25519Signature2018",
			},
		},
	}
	data, _ := json.Marshal(r)
	result := make(map[string]interface{}, 0)
	err := json.Unmarshal(data, &result)
	require.NoError(t, err)

	// single entries should not end up as slice
	assert.IsType(t, make(map[string]interface{}), result["verifiableCredential"])
	assert.IsType(t, make(map[string]interface{}), result["proof"])
	assert.IsType(t, "", result["@context"])
	assert.IsType(t, "", result["type"])
}

func Test_CompactingVerifiablePresentation_UnmarshalJSON(t *testing.T) {
	const expectedJSON = `
{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": {
    "type": "Ed25519Signature2018"
  },
  "type": "VerifiablePresentation",
  "verifiableCredential": {
    "@context": null,
    "credentialSubject": {
      "id": "did:nuts:123"
    },
    "issuer": "https://example.com",
    "proof": {
      "type": "Ed25519Signature2018"
    },
    "type": [
      "VerifiableCredential",
      "UniversityDegreeCredential"
    ]
  }
}`
	var actual CompactingVerifiablePresentation
	err := json.Unmarshal([]byte(expectedJSON), &actual)
	require.NoError(t, err)
	actualJSON, _ := actual.MarshalJSON()

	assert.JSONEq(t, expectedJSON, string(actualJSON))
}
