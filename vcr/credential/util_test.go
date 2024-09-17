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

package credential

import (
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestResolveSubjectDID(t *testing.T) {
	did1 := did.MustParseDID("did:test:123")
	did2 := did.MustParseDID("did:test:456")
	credential1 := vc.VerifiableCredential{
		CredentialSubject: []interface{}{map[string]interface{}{"id": did1}},
	}
	credential2 := vc.VerifiableCredential{
		CredentialSubject: []interface{}{map[string]interface{}{"id": did1}},
	}
	credential3 := vc.VerifiableCredential{
		CredentialSubject: []interface{}{map[string]interface{}{"id": did2}},
	}
	t.Run("all the same", func(t *testing.T) {
		actual, err := ResolveSubjectDID(credential1, credential2)
		assert.NoError(t, err)
		assert.Equal(t, did1, *actual)
	})
	t.Run("differ", func(t *testing.T) {
		actual, err := ResolveSubjectDID(credential1, credential3)
		assert.EqualError(t, err, "not all VCs have the same credentialSubject.id")
		assert.Nil(t, actual)
	})
	t.Run("no ID", func(t *testing.T) {
		actual, err := ResolveSubjectDID(vc.VerifiableCredential{CredentialSubject: []interface{}{map[string]interface{}{}}})
		assert.EqualError(t, err, "unable to get subject DID from VC: credential subjects have no ID")
		assert.Nil(t, actual)
	})
	t.Run("no credentialSubject", func(t *testing.T) {
		actual, err := ResolveSubjectDID(vc.VerifiableCredential{})
		assert.EqualError(t, err, "unable to get subject DID from VC: there must be at least 1 credentialSubject")
		assert.Nil(t, actual)
	})

}

func TestPresenterIsCredentialSubject(t *testing.T) {
	subjectDID := did.MustParseDID("did:test:123")
	keyID := ssi.MustParseURI("did:test:123#1")
	t.Run("ok", func(t *testing.T) {
		vp := test.ParsePresentation(t, vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{
					Type:               "JsonWebSignature2020",
					VerificationMethod: keyID,
				},
			},
			VerifiableCredential: []vc.VerifiableCredential{
				{
					CredentialSubject: []interface{}{map[string]interface{}{"id": subjectDID}},
				},
			},
		})
		is, err := PresenterIsCredentialSubject(vp)
		assert.NoError(t, err)
		assert.Equal(t, subjectDID, *is)
	})
	t.Run("no proof", func(t *testing.T) {
		vp := test.ParsePresentation(t, vc.VerifiablePresentation{})
		actual, err := PresenterIsCredentialSubject(vp)
		assert.EqualError(t, err, "presentation should have exactly 1 proof, got 0")
		assert.Nil(t, actual)
	})
	t.Run("no VC subject", func(t *testing.T) {
		vp := test.ParsePresentation(t, vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{
					Type:               "JsonWebSignature2020",
					VerificationMethod: keyID,
				},
			},
			VerifiableCredential: []vc.VerifiableCredential{
				{},
			},
		})
		is, err := PresenterIsCredentialSubject(vp)
		assert.EqualError(t, err, "unable to get subject DID from VC: there must be at least 1 credentialSubject")
		assert.Nil(t, is)
	})
	t.Run("no VC subject ID", func(t *testing.T) {
		vp := test.ParsePresentation(t, vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{
					Type:               "JsonWebSignature2020",
					VerificationMethod: keyID,
				},
			},
			VerifiableCredential: []vc.VerifiableCredential{
				{
					CredentialSubject: []interface{}{map[string]interface{}{}},
				},
			},
		})
		is, err := PresenterIsCredentialSubject(vp)
		assert.EqualError(t, err, "unable to get subject DID from VC: credential subjects have no ID")
		assert.Nil(t, is)
	})
	t.Run("proof verification method does not equal VC subject ID", func(t *testing.T) {
		vp := test.ParsePresentation(t, vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{
					Type:               "JsonWebSignature2020",
					VerificationMethod: keyID,
				},
			},
			VerifiableCredential: []vc.VerifiableCredential{
				{
					CredentialSubject: []interface{}{map[string]interface{}{"id": did.MustParseDID("did:test:456")}},
				},
			},
		})
		is, err := PresenterIsCredentialSubject(vp)
		assert.NoError(t, err)
		assert.Nil(t, is)
	})
	t.Run("proof type is unsupported", func(t *testing.T) {
		vp := test.ParsePresentation(t, vc.VerifiablePresentation{
			Proof: []interface{}{
				true,
			},
			VerifiableCredential: []vc.VerifiableCredential{
				{
					CredentialSubject: []interface{}{map[string]interface{}{"id": subjectDID}},
				},
			},
		})
		is, err := PresenterIsCredentialSubject(vp)
		assert.EqualError(t, err, "invalid LD-proof for presentation: json: cannot unmarshal bool into Go value of type proof.LDProof")
		assert.Nil(t, is)
	})
	t.Run("too many proofs", func(t *testing.T) {
		vp := test.ParsePresentation(t, vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{},
				proof.LDProof{},
			},
			VerifiableCredential: []vc.VerifiableCredential{
				{
					CredentialSubject: []interface{}{map[string]interface{}{"id": subjectDID}},
				},
			},
		})
		is, err := PresenterIsCredentialSubject(vp)
		assert.EqualError(t, err, "presentation should have exactly 1 proof, got 2")
		assert.Nil(t, is)
	})
}

func TestPresentationIssuanceDate(t *testing.T) {
	presenterDID := did.MustParseDID("did:test:123")
	expected := time.Now().In(time.UTC).Truncate(time.Second)
	t.Run("JWT iat", func(t *testing.T) {
		presentation, _ := test.CreateJWTPresentation(t, presenterDID, func(token jwt.Token) {
			_ = token.Remove(jwt.NotBeforeKey)
			require.NoError(t, token.Set(jwt.IssuedAtKey, expected))
		})
		actual := PresentationIssuanceDate(presentation)
		assert.Equal(t, expected, *actual)
	})
	t.Run("JWT nbf", func(t *testing.T) {
		presentation, _ := test.CreateJWTPresentation(t, presenterDID, func(token jwt.Token) {
			_ = token.Remove(jwt.IssuedAtKey)
			require.NoError(t, token.Set(jwt.NotBeforeKey, expected))
		})
		actual := PresentationIssuanceDate(presentation)
		assert.Equal(t, expected, *actual)
	})
	t.Run("JWT nbf takes precedence over iat", func(t *testing.T) {
		presentation, _ := test.CreateJWTPresentation(t, presenterDID, func(token jwt.Token) {
			require.NoError(t, token.Set(jwt.IssuedAtKey, expected.Add(time.Hour)))
			require.NoError(t, token.Set(jwt.NotBeforeKey, expected))
		})
		actual := PresentationIssuanceDate(presentation)
		assert.Equal(t, expected, *actual)
	})
	t.Run("JWT no iat or nbf", func(t *testing.T) {
		presentation, _ := test.CreateJWTPresentation(t, presenterDID, func(token jwt.Token) {
			_ = token.Remove(jwt.IssuedAtKey)
			_ = token.Remove(jwt.NotBeforeKey)
		})
		actual := PresentationIssuanceDate(presentation)
		assert.Nil(t, actual)
	})
	t.Run("JSON-LD", func(t *testing.T) {
		presentation := test.ParsePresentation(t, vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{
					ProofOptions: proof.ProofOptions{
						Created: expected,
					},
				},
			},
		})
		actual := PresentationIssuanceDate(presentation)
		assert.Equal(t, expected, *actual)
	})
	t.Run("JSON-LD no proof", func(t *testing.T) {
		presentation := test.ParsePresentation(t, vc.VerifiablePresentation{})
		actual := PresentationIssuanceDate(presentation)
		assert.Nil(t, actual)
	})
	t.Run("JSON-LD no created", func(t *testing.T) {
		presentation := test.ParsePresentation(t, vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{},
			},
		})
		actual := PresentationIssuanceDate(presentation)
		assert.Nil(t, actual)
	})
}

func TestPresentationExpirationDate(t *testing.T) {
	presenterDID := did.MustParseDID("did:test:123")
	expected := time.Now().In(time.UTC).Truncate(time.Second)
	t.Run("JWT", func(t *testing.T) {
		presentation, _ := test.CreateJWTPresentation(t, presenterDID, func(token jwt.Token) {
			require.NoError(t, token.Set(jwt.ExpirationKey, expected))
		})
		actual := PresentationExpirationDate(presentation)
		assert.Equal(t, expected, *actual)
	})
	t.Run("JWT no exp", func(t *testing.T) {
		presentation, _ := test.CreateJWTPresentation(t, presenterDID, func(token jwt.Token) {
			_ = token.Remove(jwt.ExpirationKey)
		})
		actual := PresentationExpirationDate(presentation)
		assert.Nil(t, actual)
	})
	t.Run("JSON-LD", func(t *testing.T) {
		presentation := test.ParsePresentation(t, vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{
					ProofOptions: proof.ProofOptions{
						Expires: &expected,
					},
				},
			},
		})
		actual := PresentationExpirationDate(presentation)
		assert.Equal(t, expected, *actual)
	})
	t.Run("JSON-LD no proof", func(t *testing.T) {
		presentation := test.ParsePresentation(t, vc.VerifiablePresentation{})
		actual := PresentationExpirationDate(presentation)
		assert.Nil(t, actual)
	})
	t.Run("JSON-LD no expires", func(t *testing.T) {
		presentation := test.ParsePresentation(t, vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{},
			},
		})
		actual := PresentationExpirationDate(presentation)
		assert.Nil(t, actual)
	})
}

func TestAutoCorrectSelfAttestedCredential(t *testing.T) {
	requestor := did.MustParseDID("did:test:123")
	credential := vc.VerifiableCredential{
		CredentialSubject: make([]interface{}, 1),
	}
	result := AutoCorrectSelfAttestedCredential(credential, requestor)
	assert.Equal(t, requestor.URI(), result.Issuer)
	assert.NotEqual(t, time.Time{}, result.IssuanceDate)
	assert.NotEqual(t, "", result.ID.String())
	assert.Equal(t, requestor.String(), result.CredentialSubject[0].(map[string]interface{})["id"])
}

func TestFilterOnDIDMethod(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		credentials := []vc.VerifiableCredential{
			{
				Issuer: ssi.MustParseURI("did:test:123"),
				CredentialSubject: []interface{}{
					map[string]interface{}{"id": ssi.MustParseURI("did:test:456")},
				},
			},
		}

		result := FilterOnDIDMethod(credentials, []string{"test"})

		assert.Len(t, result, 1)
	})
	t.Run("no match on issuer", func(t *testing.T) {
		credentials := []vc.VerifiableCredential{
			{
				Issuer: ssi.MustParseURI("did:test:123"),
			},
		}

		result := FilterOnDIDMethod(credentials, []string{"other"})

		assert.Len(t, result, 0)
	})
	t.Run("no match on credentialSubject", func(t *testing.T) {
		credentials := []vc.VerifiableCredential{
			{
				CredentialSubject: []interface{}{
					map[string]interface{}{"id": ssi.MustParseURI("did:test:456")},
				},
			},
		}

		result := FilterOnDIDMethod(credentials, []string{"other"})

		assert.Len(t, result, 0)
	})
	t.Run("issuer not a DID", func(t *testing.T) {
		credentials := []vc.VerifiableCredential{
			{
				Issuer: ssi.MustParseURI("client_id"),
			},
		}

		result := FilterOnDIDMethod(credentials, []string{"test"})

		assert.Len(t, result, 1)
	})
	t.Run("credentialSubject not a did", func(t *testing.T) {
		credentials := []vc.VerifiableCredential{
			{
				CredentialSubject: []interface{}{
					map[string]interface{}{"id": ssi.MustParseURI("client_id")},
				},
			},
		}

		result := FilterOnDIDMethod(credentials, []string{"test"})

		assert.Len(t, result, 1)
	})
	bug := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://nuts.nl/credentials/v1",
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
  ],
  "credentialSubject": {
    "id": "did:web:nodeB:iam:f17d021a-f0e6-4ed9-a22a-e4447f1720ba",
    "organization": {
      "city": "Caretown",
      "name": "Caresoft B.V."
    }
  },
  "id": "did:web:nodeB:iam:f17d021a-f0e6-4ed9-a22a-e4447f1720ba#36b83620-13b2-4fbf-a57a-618731839a6f",
  "issuanceDate": "2024-09-17T06:44:57.97676521Z",
  "issuer": "did:web:nodeB:iam:f17d021a-f0e6-4ed9-a22a-e4447f1720ba",
  "proof": {
    "created": "2024-09-17T06:44:57.97676521Z",
    "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il0sImtpZCI6ImRpZDp3ZWI6bm9kZUI6aWFtOmYxN2QwMjFhLWYwZTYtNGVkOS1hMjJhLWU0NDQ3ZjE3MjBiYSM3YTExZTIxZi05ZWYwLTQ5NTctOTM4Zi0xZTUyZTE5NTc1M2QifQ..4t6XiCFkvl3swZkpN63xvRUcTwMj5uUP2wVpkAmQXg33Jaou6JEgi_gwnygTK1C_bfwaqa6X7cMvT5Fm0cwTEA",
    "proofPurpose": "assertionMethod",
    "type": "JsonWebSignature2020",
    "verificationMethod": "did:web:nodeB:iam:f17d021a-f0e6-4ed9-a22a-e4447f1720ba#7a11e21f-9ef0-4957-938f-1e52e195753d"
  },
  "type": [
    "NutsOrganizationCredential",
    "VerifiableCredential"
  ]
}
`
	t.Run("foo", func(t *testing.T) {
		c := vc.VerifiableCredential{}
		_ = c.UnmarshalJSON([]byte(bug))
		credentials := []vc.VerifiableCredential{c}

		result := FilterOnDIDMethod(credentials, []string{"web"})

		assert.Len(t, result, 1)
	})
}
