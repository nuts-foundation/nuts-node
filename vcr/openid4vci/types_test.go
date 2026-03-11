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

import (
	"encoding/json"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredentialRequest_V1Spec tests that CredentialRequest conforms to OpenID4VCI v1.0 Section 8.2
func TestCredentialRequest_V1Spec(t *testing.T) {
	t.Run("request with credential_configuration_id", func(t *testing.T) {
		requestJSON := `{
			"credential_configuration_id": "NutsAuthorizationCredential_ldp_vc",
			"proofs": {
				"jwt": ["eyJ..."]
			}
		}`

		var request CredentialRequest
		err := json.Unmarshal([]byte(requestJSON), &request)
		require.NoError(t, err)

		assert.Equal(t, "NutsAuthorizationCredential_ldp_vc", request.CredentialConfigurationID)
		assert.NotNil(t, request.Proofs)
	})

	t.Run("marshaling only includes non-empty fields", func(t *testing.T) {
		request := CredentialRequest{
			CredentialConfigurationID: "NutsAuthorizationCredential_ldp_vc",
			Proofs: &CredentialRequestProofs{
				Jwt: []string{"eyJ..."},
			},
		}

		jsonBytes, err := json.Marshal(request)
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(jsonBytes, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "NutsAuthorizationCredential_ldp_vc", parsed["credential_configuration_id"])
	})
}

// TestCredentialOffer_V1Spec tests that CredentialOffer conforms to OpenID4VCI v1.0 Section 4.1.1
func TestCredentialOffer_V1Spec(t *testing.T) {
	t.Run("v1.0 format with credential_configuration_ids", func(t *testing.T) {
		// Per v1.0 Section 4.1.1
		offerJSON := `{
			"credential_issuer": "https://issuer.example.com",
			"credential_configuration_ids": ["NutsAuthorizationCredential_ldp_vc"],
			"grants": {
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					"pre-authorized_code": "secret123"
				}
			}
		}`

		var offer CredentialOffer
		err := json.Unmarshal([]byte(offerJSON), &offer)
		require.NoError(t, err)

		assert.Equal(t, "https://issuer.example.com", offer.CredentialIssuer)
		assert.Equal(t, []string{"NutsAuthorizationCredential_ldp_vc"}, offer.CredentialConfigurationIDs)
		require.NotNil(t, offer.Grants.PreAuthorizedCode)
		assert.Equal(t, "secret123", offer.Grants.PreAuthorizedCode.PreAuthorizedCode)
	})

	t.Run("marshaling preserves v1.0 format", func(t *testing.T) {
		offer := CredentialOffer{
			CredentialIssuer:           "https://issuer.example.com",
			CredentialConfigurationIDs: []string{"NutsAuthorizationCredential_ldp_vc"},
			Grants: &CredentialOfferGrants{
				PreAuthorizedCode: &PreAuthorizedCodeParams{
					PreAuthorizedCode: "secret123",
				},
			},
		}

		jsonBytes, err := json.Marshal(offer)
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(jsonBytes, &parsed)
		require.NoError(t, err)

		// Must use credential_configuration_ids (v1.0), NOT credentials (old format)
		_, hasOldField := parsed["credentials"]
		assert.False(t, hasOldField, "should not have old 'credentials' field")

		configIds, ok := parsed["credential_configuration_ids"].([]interface{})
		require.True(t, ok, "must have credential_configuration_ids array")
		assert.Len(t, configIds, 1)
		assert.Equal(t, "NutsAuthorizationCredential_ldp_vc", configIds[0])

		// Verify grants are serialized with the correct JSON key
		grants, ok := parsed["grants"].(map[string]interface{})
		require.True(t, ok)
		preAuth, ok := grants[PreAuthorizedCodeGrant].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "secret123", preAuth["pre-authorized_code"])
	})
}

// TestCredentialIssuerMetadata_V1Spec tests that metadata conforms to OpenID4VCI v1.0 Section 11.2.1
func TestCredentialIssuerMetadata_V1Spec(t *testing.T) {
	t.Run("v1.0 format with credential_configurations_supported map", func(t *testing.T) {
		// Per v1.0 Section 11.2.1
		metadataJSON := `{
			"credential_issuer": "https://issuer.example.com",
			"credential_endpoint": "https://issuer.example.com/credential",
			"credential_configurations_supported": {
				"NutsAuthorizationCredential_ldp_vc": {
					"format": "ldp_vc",
					"cryptographic_binding_methods_supported": ["did:nuts"],
					"credential_definition": {
						"@context": ["https://www.w3.org/2018/credentials/v1", "https://nuts.nl/credentials/v1"],
						"type": ["VerifiableCredential", "NutsAuthorizationCredential"]
					}
				}
			}
		}`

		var metadata CredentialIssuerMetadata
		err := json.Unmarshal([]byte(metadataJSON), &metadata)
		require.NoError(t, err)

		assert.Equal(t, "https://issuer.example.com", metadata.CredentialIssuer)
		assert.Equal(t, "https://issuer.example.com/credential", metadata.CredentialEndpoint)

		// Must be a map keyed by credential_configuration_id
		require.Len(t, metadata.CredentialConfigurationsSupported, 1)
		config, ok := metadata.CredentialConfigurationsSupported["NutsAuthorizationCredential_ldp_vc"]
		require.True(t, ok)
		assert.Equal(t, "ldp_vc", config["format"])
	})

	t.Run("marshaling preserves v1.0 format", func(t *testing.T) {
		metadata := CredentialIssuerMetadata{
			CredentialIssuer:   "https://issuer.example.com",
			CredentialEndpoint: "https://issuer.example.com/credential",
			CredentialConfigurationsSupported: map[string]map[string]interface{}{
				"NutsAuthorizationCredential_ldp_vc": {
					"format": "ldp_vc",
				},
			},
		}

		jsonBytes, err := json.Marshal(metadata)
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(jsonBytes, &parsed)
		require.NoError(t, err)

		// Must use credential_configurations_supported (v1.0), NOT credentials_supported (old format)
		_, hasOldField := parsed["credentials_supported"]
		assert.False(t, hasOldField, "should not have old 'credentials_supported' field")

		configs, ok := parsed["credential_configurations_supported"].(map[string]interface{})
		require.True(t, ok, "must have credential_configurations_supported object")
		assert.Contains(t, configs, "NutsAuthorizationCredential_ldp_vc")
	})
}

// TestCredentialResponse_V1Spec tests that CredentialResponse conforms to OpenID4VCI v1.0 Section 8.3
// v1.0 uses `credentials` (array of wrapper objects with `credential` key) and c_nonce is no longer in the response.
func TestCredentialResponse_V1Spec(t *testing.T) {
	t.Run("response uses credentials array with credential wrapper", func(t *testing.T) {
		credJSON, _ := json.Marshal(map[string]interface{}{"issuer": "did:nuts:issuer"})
		response := CredentialResponse{
			Credentials: []CredentialResponseEntry{{Credential: credJSON}},
		}

		jsonBytes, err := json.Marshal(response)
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(jsonBytes, &parsed)
		require.NoError(t, err)

		// Must use credentials (plural), not credential (singular) at top level
		_, hasSingular := parsed["credential"]
		assert.False(t, hasSingular, "must use credentials (plural) not credential (singular) at top level")

		// Each element in credentials must be a wrapper with a "credential" key
		credentialsArr, ok := parsed["credentials"].([]interface{})
		require.True(t, ok, "credentials must be an array")
		require.Len(t, credentialsArr, 1)
		entry, ok := credentialsArr[0].(map[string]interface{})
		require.True(t, ok, "each credentials entry must be an object")
		assert.NotNil(t, entry["credential"], "each entry must have a credential key")
	})

	t.Run("response does not contain c_nonce fields", func(t *testing.T) {
		credJSON, _ := json.Marshal(map[string]interface{}{"issuer": "did:nuts:issuer"})
		response := CredentialResponse{
			Credentials: []CredentialResponseEntry{{Credential: credJSON}},
		}

		jsonBytes, err := json.Marshal(response)
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(jsonBytes, &parsed)
		require.NoError(t, err)

		_, hasExpiresIn := parsed["c_nonce_expires_in"]
		assert.False(t, hasExpiresIn, "c_nonce_expires_in must be absent when not set")
	})
}

func TestProofSigningAlgValues(t *testing.T) {
	t.Run("returns values when present", func(t *testing.T) {
		config := map[string]interface{}{
			"proof_types_supported": map[string]interface{}{
				"jwt": map[string]interface{}{
					"proof_signing_alg_values_supported": []interface{}{"ES256", "ES384"},
				},
			},
		}
		result, err := ProofSigningAlgValues(config)
		require.NoError(t, err)
		assert.Equal(t, []string{"ES256", "ES384"}, result)
	})
	t.Run("returns nil when proof_types_supported absent", func(t *testing.T) {
		config := map[string]interface{}{"format": "ldp_vc"}
		result, err := ProofSigningAlgValues(config)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
	t.Run("returns nil when jwt absent in proof_types_supported", func(t *testing.T) {
		config := map[string]interface{}{
			"proof_types_supported": map[string]interface{}{
				"cwt": map[string]interface{}{},
			},
		}
		result, err := ProofSigningAlgValues(config)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
	t.Run("error - jwt present but proof_signing_alg_values_supported absent", func(t *testing.T) {
		config := map[string]interface{}{
			"proof_types_supported": map[string]interface{}{
				"jwt": map[string]interface{}{},
			},
		}
		result, err := ProofSigningAlgValues(config)
		assert.Nil(t, result)
		assert.EqualError(t, err, "issuer metadata has proof_types_supported.jwt but is missing proof_signing_alg_values_supported")
	})
	t.Run("skips non-string values in algorithm array", func(t *testing.T) {
		config := map[string]interface{}{
			"proof_types_supported": map[string]interface{}{
				"jwt": map[string]interface{}{
					"proof_signing_alg_values_supported": []interface{}{"ES256", 42, "ES384"},
				},
			},
		}
		result, err := ProofSigningAlgValues(config)
		require.NoError(t, err)
		assert.Equal(t, []string{"ES256", "ES384"}, result)
	})
}

func TestValidateProofSigningAlg(t *testing.T) {
	t.Run("ok - algorithm is supported", func(t *testing.T) {
		assert.NoError(t, ValidateProofSigningAlg("ES256", []string{"ES256", "ES384"}))
	})
	t.Run("ok - no constraint when supportedAlgs is empty", func(t *testing.T) {
		assert.NoError(t, ValidateProofSigningAlg("ES256", nil))
	})
	t.Run("error - algorithm not supported", func(t *testing.T) {
		err := ValidateProofSigningAlg("ES256", []string{"ES384", "ES512"})
		assert.EqualError(t, err, "signing algorithm ES256 is not supported by issuer (supported: ES384, ES512)")
	})
}

// TestCredentialDefinition_Validation tests credential definition validation
func TestCredentialDefinition_Validation(t *testing.T) {
	t.Run("valid definition", func(t *testing.T) {
		def := &CredentialDefinition{
			Context: []ssi.URI{
				ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
				ssi.MustParseURI("https://nuts.nl/credentials/v1"),
			},
			Type: []ssi.URI{
				ssi.MustParseURI("VerifiableCredential"),
				ssi.MustParseURI("NutsAuthorizationCredential"),
			},
		}

		err := def.Validate(true)
		assert.NoError(t, err)
	})

	t.Run("credentialSubject not allowed in offer", func(t *testing.T) {
		subject := map[string]interface{}{"id": "did:example:123"}
		def := &CredentialDefinition{
			Context: []ssi.URI{
				ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
			},
			Type: []ssi.URI{
				ssi.MustParseURI("VerifiableCredential"),
			},
			CredentialSubject: subject,
		}

		err := def.Validate(true)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "credentialSubject not allowed")
	})
}
