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
// The spec states that credential request MUST contain ONE of:
// - credential_configuration_id: string referencing metadata
// - format + format-specific parameters (e.g., credential_definition for ldp_vc)
func TestCredentialRequest_V1Spec(t *testing.T) {
	t.Run("request with credential_configuration_id only (v1.0 preferred)", func(t *testing.T) {
		// Per v1.0 Section 8.2: "credential_configuration_id: REQUIRED when the credential_configuration_id
		// parameter was not present in the Credential Offer"
		// This is the simpler approach - just reference the configuration by ID
		requestJSON := `{
			"credential_configuration_id": "NutsAuthorizationCredential_ldp_vc",
			"proof": {
				"proof_type": "jwt",
				"jwt": "eyJ..."
			}
		}`

		var request CredentialRequest
		err := json.Unmarshal([]byte(requestJSON), &request)
		require.NoError(t, err)

		assert.Equal(t, "NutsAuthorizationCredential_ldp_vc", request.CredentialConfigurationId)
		assert.Empty(t, request.Format, "format should not be required when using credential_configuration_id")
		assert.NotNil(t, request.Proof)
	})

	t.Run("request with format + credential_definition (explicit approach)", func(t *testing.T) {
		// Per v1.0 Appendix A.1.2 for ldp_vc format
		requestJSON := `{
			"format": "ldp_vc",
			"credential_definition": {
				"@context": ["https://www.w3.org/2018/credentials/v1", "https://nuts.nl/credentials/v1"],
				"type": ["VerifiableCredential", "NutsAuthorizationCredential"]
			},
			"proof": {
				"proof_type": "jwt",
				"jwt": "eyJ..."
			}
		}`

		var request CredentialRequest
		err := json.Unmarshal([]byte(requestJSON), &request)
		require.NoError(t, err)

		assert.Empty(t, request.CredentialConfigurationId)
		assert.Equal(t, "ldp_vc", request.Format)
		assert.NotNil(t, request.CredentialDefinition)
		assert.Len(t, request.CredentialDefinition.Context, 2)
		assert.Len(t, request.CredentialDefinition.Type, 2)
	})

	t.Run("marshaling request with credential_configuration_id omits format and credential_definition", func(t *testing.T) {
		request := CredentialRequest{
			CredentialConfigurationId: "NutsAuthorizationCredential_ldp_vc",
			Proof: &CredentialRequestProof{
				ProofType: "jwt",
				Jwt:       "eyJ...",
			},
		}

		jsonBytes, err := json.Marshal(request)
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(jsonBytes, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "NutsAuthorizationCredential_ldp_vc", parsed["credential_configuration_id"])
		_, hasFormat := parsed["format"]
		assert.False(t, hasFormat, "format must be absent when using credential_configuration_id")
		_, hasCredDef := parsed["credential_definition"]
		assert.False(t, hasCredDef, "credential_definition must be absent when using credential_configuration_id")
	})

	t.Run("marshaling request with format omits credential_configuration_id", func(t *testing.T) {
		request := CredentialRequest{
			Format: "ldp_vc",
			CredentialDefinition: &CredentialDefinition{
				Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
				Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential")},
			},
			Proof: &CredentialRequestProof{
				ProofType: "jwt",
				Jwt:       "eyJ...",
			},
		}

		jsonBytes, err := json.Marshal(request)
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(jsonBytes, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "ldp_vc", parsed["format"])
		assert.NotNil(t, parsed["credential_definition"])
		_, hasConfigID := parsed["credential_configuration_id"]
		assert.False(t, hasConfigID, "credential_configuration_id must be absent when using format")
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
		assert.Equal(t, []string{"NutsAuthorizationCredential_ldp_vc"}, offer.CredentialConfigurationIds)
		require.NotNil(t, offer.Grants.PreAuthorizedCode)
		assert.Equal(t, "secret123", offer.Grants.PreAuthorizedCode.PreAuthorizedCode)
	})

	t.Run("marshaling preserves v1.0 format", func(t *testing.T) {
		offer := CredentialOffer{
			CredentialIssuer:           "https://issuer.example.com",
			CredentialConfigurationIds: []string{"NutsAuthorizationCredential_ldp_vc"},
			Grants: CredentialOfferGrants{
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
// v1.0 removed the format field from the response (it was REQUIRED in Draft 11, removed in Draft 12+)
func TestCredentialResponse_V1Spec(t *testing.T) {
	t.Run("response does not contain format field", func(t *testing.T) {
		cred := map[string]interface{}{"issuer": "did:nuts:issuer"}
		response := CredentialResponse{
			Credential: cred,
		}

		jsonBytes, err := json.Marshal(response)
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(jsonBytes, &parsed)
		require.NoError(t, err)

		_, hasFormat := parsed["format"]
		assert.False(t, hasFormat, "format must not be present in v1.0 credential response")
		assert.NotNil(t, parsed["credential"])
	})

	t.Run("c_nonce is absent when not set", func(t *testing.T) {
		cred := map[string]interface{}{"issuer": "did:nuts:issuer"}
		response := CredentialResponse{
			Credential: cred,
		}

		jsonBytes, err := json.Marshal(response)
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(jsonBytes, &parsed)
		require.NoError(t, err)

		_, hasCNonce := parsed["c_nonce"]
		assert.False(t, hasCNonce, "c_nonce must be absent when not set")
	})

	t.Run("c_nonce is present when set", func(t *testing.T) {
		cred := map[string]interface{}{"issuer": "did:nuts:issuer"}
		nonce := "some-nonce"
		response := CredentialResponse{
			Credential: cred,
			CNonce:     &nonce,
		}

		jsonBytes, err := json.Marshal(response)
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(jsonBytes, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "some-nonce", parsed["c_nonce"])
	})
	t.Run("c_nonce_expires_in is present when set alongside c_nonce", func(t *testing.T) {
		cred := map[string]interface{}{"issuer": "did:nuts:issuer"}
		nonce := "some-nonce"
		expiresIn := 300
		response := CredentialResponse{
			Credential:      cred,
			CNonce:          &nonce,
			CNonceExpiresIn: &expiresIn,
		}

		jsonBytes, err := json.Marshal(response)
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(jsonBytes, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "some-nonce", parsed["c_nonce"])
		assert.Equal(t, float64(300), parsed["c_nonce_expires_in"])
	})
	t.Run("c_nonce_expires_in is absent when not set", func(t *testing.T) {
		cred := map[string]interface{}{"issuer": "did:nuts:issuer"}
		response := CredentialResponse{
			Credential: cred,
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
