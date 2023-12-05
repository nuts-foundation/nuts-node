/*
 * Nuts node
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

package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/stretchr/testify/require"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
)

func TestFindValidator(t *testing.T) {
	t.Run("an unknown type returns the default validator", func(t *testing.T) {
		v := FindValidator(vc.VerifiableCredential{})

		assert.NotNil(t, t, v)
	})

	t.Run("validator and builder found for NutsOrganizationCredential", func(t *testing.T) {
		vc := ValidNutsOrganizationCredential(t)
		v := FindValidator(vc)

		assert.NotNil(t, v)
	})

	t.Run("validator and builder found for NutsAuthorizationCredential", func(t *testing.T) {
		vc := ValidNutsAuthorizationCredential()
		v := FindValidator(*vc)

		assert.NotNil(t, v)
	})
}

func TestExtractTypes(t *testing.T) {
	v := vc.VerifiableCredential{
		Type: []ssi.URI{vc.VerifiableCredentialTypeV1URI(), *NutsOrganizationCredentialTypeURI},
	}

	types := ExtractTypes(v)

	assert.Len(t, types, 1)
	assert.Equal(t, NutsOrganizationCredentialType, types[0])
}

func TestPresentationSigner(t *testing.T) {
	keyID := did.MustParseDIDURL("did:example:issuer#1")
	t.Run("JWT", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		t.Run("ok", func(t *testing.T) {
			token := jwt.New()
			require.NoError(t, token.Set(jwt.IssuerKey, keyID.DID.String()))
			signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, privateKey))
			require.NoError(t, err)
			presentation, err := vc.ParseVerifiablePresentation(string(signedToken))
			require.NoError(t, err)

			actual, err := PresentationSigner(*presentation)
			require.NoError(t, err)
			assert.Equal(t, keyID.DID, *actual)
		})
		t.Run("missing 'iss' claim", func(t *testing.T) {
			token := jwt.New()
			signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, privateKey))
			require.NoError(t, err)
			presentation, err := vc.ParseVerifiablePresentation(string(signedToken))
			require.NoError(t, err)

			actual, err := PresentationSigner(*presentation)
			assert.EqualError(t, err, "JWT presentation does not have 'iss' claim")
			assert.Nil(t, actual)
		})
	})
	t.Run("JSON-LD", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			presentation := test.ParsePresentation(t, vc.VerifiablePresentation{
				Proof: []interface{}{proof.LDProof{
					VerificationMethod: keyID.URI(),
				}},
			})
			actual, err := PresentationSigner(presentation)
			require.NoError(t, err)
			assert.Equal(t, keyID.DID, *actual)
		})
		t.Run("too many proofs", func(t *testing.T) {
			presentation := test.ParsePresentation(t, vc.VerifiablePresentation{
				Proof: []interface{}{proof.LDProof{
					VerificationMethod: keyID.URI(),
				}, proof.LDProof{
					VerificationMethod: keyID.URI(),
				}},
			})
			actual, err := PresentationSigner(presentation)
			assert.EqualError(t, err, "presentation should have exactly 1 proof, got 2")
			assert.Nil(t, actual)
		})
		t.Run("not a JSON-LD proof", func(t *testing.T) {
			presentation := test.ParsePresentation(t, vc.VerifiablePresentation{
				Proof: []interface{}{5},
			})
			actual, err := PresentationSigner(presentation)
			assert.EqualError(t, err, "invalid LD-proof for presentation: json: cannot unmarshal number into Go value of type proof.LDProof")
			assert.Nil(t, actual)
		})
		t.Run("invalid DID in proof", func(t *testing.T) {
			presentation := test.ParsePresentation(t, vc.VerifiablePresentation{
				Proof: []interface{}{proof.LDProof{
					VerificationMethod: ssi.MustParseURI("foo"),
				}},
			})
			actual, err := PresentationSigner(presentation)
			assert.EqualError(t, err, "invalid verification method for JSON-LD presentation: invalid DID")
			assert.Nil(t, actual)
		})
		t.Run("empty VerificationMethod", func(t *testing.T) {
			presentation := test.ParsePresentation(t, vc.VerifiablePresentation{
				Proof: []interface{}{proof.LDProof{
					VerificationMethod: ssi.MustParseURI(""),
				}},
			})
			actual, err := PresentationSigner(presentation)
			assert.ErrorContains(t, err, "invalid verification method for JSON-LD presentation")
			assert.Nil(t, actual)
		})
	})
	t.Run("unsupported format", func(t *testing.T) {
		presentation := vc.VerifiablePresentation{}
		actual, err := PresentationSigner(presentation)
		assert.EqualError(t, err, "unsupported presentation format: ")
		assert.Nil(t, actual)
	})
}
