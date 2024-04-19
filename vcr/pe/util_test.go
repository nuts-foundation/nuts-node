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
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParseEnvelope(t *testing.T) {
	t.Run("JWT", func(t *testing.T) {
		presentation, _ := test.CreateJWTPresentation(t, did.MustParseDID("did:example:1"), nil, test.ValidNutsOrganizationCredential(t))
		envelope, err := ParseEnvelope([]byte(presentation.Raw()))
		require.NoError(t, err)
		require.Equal(t, presentation.ID.String(), envelope.asInterface.(map[string]interface{})["id"])
		require.Len(t, envelope.Presentations, 1)
	})
	t.Run("invalid JWT", func(t *testing.T) {
		envelope, err := ParseEnvelope([]byte(`eyINVALID`))
		assert.EqualError(t, err, "unable to parse PEX envelope as verifiable presentation: invalid JWT")
		assert.Nil(t, envelope)
	})
	t.Run("JSON object", func(t *testing.T) {
		envelope, err := ParseEnvelope([]byte(`{"id": "value"}`))
		require.NoError(t, err)
		require.Equal(t, map[string]interface{}{"id": "value"}, envelope.asInterface)
		require.Len(t, envelope.Presentations, 1)
	})
	t.Run("invalid VP as JSON object", func(t *testing.T) {
		envelope, err := ParseEnvelope([]byte(`{"id": true}`))
		assert.ErrorContains(t, err, "unable to parse PEX envelope as verifiable presentation")
		assert.Nil(t, envelope)
	})
	t.Run("JSON array with objects", func(t *testing.T) {
		envelope, err := ParseEnvelope([]byte(`[{"id": "value"}]`))
		require.NoError(t, err)
		require.Equal(t, []interface{}{map[string]interface{}{"id": "value"}}, envelope.asInterface)
		require.Len(t, envelope.Presentations, 1)
	})
	t.Run("JSON array with JWTs", func(t *testing.T) {
		presentation, _ := test.CreateJWTPresentation(t, did.MustParseDID("did:example:1"), nil, test.ValidNutsOrganizationCredential(t))
		presentations := []string{presentation.Raw(), presentation.Raw()}
		listJSON, _ := json.Marshal(presentations)
		envelope, err := ParseEnvelope(listJSON)
		require.NoError(t, err)
		require.Len(t, envelope.asInterface, 2)
		require.Len(t, envelope.Presentations, 2)
	})
	t.Run("invalid VPs list as JSON", func(t *testing.T) {
		envelope, err := ParseEnvelope([]byte(`[{"id": true}]`))
		assert.ErrorContains(t, err, "unable to parse PEX envelope as verifiable presentation")
		assert.Nil(t, envelope)
	})
	t.Run("invalid format", func(t *testing.T) {
		envelope, err := ParseEnvelope([]byte(`true`))
		assert.EqualError(t, err, "unable to parse PEX envelope as verifiable presentation: invalid JWT")
		assert.Nil(t, envelope)
	})
}

func TestEnvelope_JSONMarshalling(t *testing.T) {
	t.Run("JWT (marshalled as string)", func(t *testing.T) {
		presentation, _ := test.CreateJWTPresentation(t, did.MustParseDID("did:example:1"), nil, test.ValidNutsOrganizationCredential(t))
		expected := presentation.Raw()

		envelope, err := ParseEnvelope([]byte(expected))
		require.NoError(t, err)
		asJSON, err := json.Marshal(envelope)
		require.NoError(t, err)
		err = json.Unmarshal(asJSON, &envelope)
		require.NoError(t, err)

		require.Equal(t, expected, string(envelope.raw))
	})
	t.Run("JSON object", func(t *testing.T) {
		expectedJSON := `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
  ],
  "id": "did:web:nodeB#639f78bf-a95b-4ffd-92de-bf4031a456ed",
  "proof": {
    "challenge": "vbyZ6EVMhK4A5zv0V3S97vGwJe3khUBw2Z46ui0hm5U",
    "created": "2024-04-19T10:09:18.649110584Z",
    "domain": "did:web:nodeA",
    "expires": "2024-04-19T10:24:18.648767413Z",
    "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il0sImtpZCI6ImRpZDp3ZWI6bm9kZUIjMCJ9..Abx-L1yXkcSkL8Ec8Md0fQ5kqn_AmMD_6cGuiC_mSMWzOxTz3lRZpDttGdx4GIxprAGqK4mSupIqjcpBuK7Gkg",
    "nonce": "vbyZ6EVMhK4A5zv0V3S97vGwJe3khUBw2Z46ui0hm5U",
    "proofPurpose": "assertionMethod",
    "type": "JsonWebSignature2020",
    "verificationMethod": "did:web:nodeB#0"
  },
  "type": "VerifiablePresentation",
  "verifiableCredential": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://nuts.nl/credentials/v1",
      "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
    ],
    "credentialSubject": {
      "id": "did:web:nodeB",
      "organization": {
        "city": "Caretown",
        "name": "Caresoft+B.V."
      }
    },
    "id": "did:web:nodeB#8f29c638-3c31-448b-9da6-6cd44def9c10",
    "issuanceDate": "2024-04-19T10:09:18.554015056Z",
    "issuer": "did:web:nodeB",
    "proof": {
      "created": "2024-04-19T10:09:18.554015056Z",
      "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il0sImtpZCI6ImRpZDp3ZWI6bm9kZUIjMCJ9..hFr9XnrazNDbDz9YzydA12otVUdkrUtN5PqxMbUVj5SL3UpEAYDUOLaLOEKfckGtzseUI9O2Y-i04CdlohonYw",
      "proofPurpose": "assertionMethod",
      "type": "JsonWebSignature2020",
      "verificationMethod": "did:web:nodeB#0"
    },
    "type": [
      "NutsOrganizationCredential",
      "VerifiableCredential"
    ]
  }
}`

		expectedEnvelope, err := ParseEnvelope([]byte(expectedJSON))
		require.NoError(t, err)
		asJSON, err := json.Marshal(expectedEnvelope)
		require.NoError(t, err)
		var actualEnvelope Envelope
		err = json.Unmarshal(asJSON, &actualEnvelope)
		require.NoError(t, err)

		require.JSONEq(t, expectedJSON, string(asJSON))
		require.Equal(t, expectedEnvelope.asInterface, actualEnvelope.asInterface)
	})
	t.Run("JSON array", func(t *testing.T) {
		presentation, _ := test.CreateJWTPresentation(t, did.MustParseDID("did:example:1"), nil, test.ValidNutsOrganizationCredential(t))
		presentations := []string{presentation.Raw(), presentation.Raw()}
		expected, _ := json.Marshal(presentations)

		envelope, err := ParseEnvelope(expected)
		require.NoError(t, err)
		asJSON, err := json.Marshal(envelope)
		require.NoError(t, err)
		err = json.Unmarshal(asJSON, &envelope)
		require.NoError(t, err)

		require.JSONEq(t, string(expected), string(envelope.raw))
	})
}
