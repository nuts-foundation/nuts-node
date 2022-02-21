/*
 * Copyright (C) 2022 Nuts community
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

package issuer

import (
	"encoding/json"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func Test_issuer_buildVC(t *testing.T) {
	credentialType, _ := ssi.ParseURI("TestCredential")
	issuerID, _ := ssi.ParseURI("did:nuts:123")
	issuerDID, _ := did.ParseDID(issuerID.String())

	t.Run("it issues a VC", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		kid := "did:nuts:123#abc"

		keyResolverMock := NewMockkeyResolver(ctrl)
		keyResolverMock.EXPECT().ResolveAssertionKey(gomock.Any()).Return(crypto.NewTestKey(kid), nil)
		contextLoader, _ := signature.NewContextLoader(false)
		sut := issuer{keyResolver: keyResolverMock, contextLoader: contextLoader}
		schemaOrgContext, _ := ssi.ParseURI("https://schema.org")

		issuance, err := time.Parse(time.RFC3339, "2022-01-02T12:00:00Z")
		assert.NoError(t, err)

		credentialOptions := vc.VerifiableCredential{
			Context:      []ssi.URI{*schemaOrgContext},
			Type:         []ssi.URI{*credentialType},
			Issuer:       *issuerID,
			IssuanceDate: issuance,
			CredentialSubject: []interface{}{map[string]interface{}{
				"id": "did:nuts:456",
			}},
		}
		result, err := sut.buildVC(credentialOptions)
		if !assert.NoError(t, err) || !assert.NotNil(t, result) {
			return
		}
		assert.Contains(t, result.Type, *credentialType, "expected vc to be of right type")
		proofs, _ := result.Proofs()
		assert.Equal(t, kid, proofs[0].VerificationMethod.String(), "expected to be signed with the kid")
		assert.Equal(t, issuerID.String(), result.Issuer.String(), "expected correct issuer")
		assert.Contains(t, result.Context, *schemaOrgContext)
		assert.Contains(t, result.Context, vc.VCContextV1URI())
		assert.Equal(t, issuance, proofs[0].Created)
	})

	t.Run("error - invalid params", func(t *testing.T) {
		t.Run("wrong amount of credential types", func(t *testing.T) {
			sut := issuer{}

			credentialOptions := vc.VerifiableCredential{
				Type: []ssi.URI{},
			}
			result, err := sut.buildVC(credentialOptions)

			assert.EqualError(t, err, "can only issue credential with 1 type")
			assert.Nil(t, result)
		})

		t.Run("missing issuer", func(t *testing.T) {
			sut := issuer{}

			credentialOptions := vc.VerifiableCredential{
				Type: []ssi.URI{*credentialType},
			}
			result, err := sut.buildVC(credentialOptions)

			assert.EqualError(t, err, "failed to parse issuer: invalid DID: input length is less than 7")
			assert.Nil(t, result)
		})
	})

	t.Run("error - returned from used services", func(t *testing.T) {
		t.Run("no assertionKey for issuer", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(*issuerDID).Return(nil, errors.New("b00m!"))
			sut := issuer{keyResolver: keyResolverMock}
			schemaOrgContext, _ := ssi.ParseURI("http://schema.org")

			credentialOptions := vc.VerifiableCredential{
				Context: []ssi.URI{*schemaOrgContext},
				Type:    []ssi.URI{*credentialType},
				Issuer:  *issuerID,
				CredentialSubject: []interface{}{map[string]interface{}{
					"id": "did:nuts:456",
				}},
			}
			_, err := sut.buildVC(credentialOptions)
			assert.EqualError(t, err, "failed to sign credential, could not resolve an assertionKey for issuer: b00m!")
		})

	})
}

func Test_issuer_Issue(t *testing.T) {
	credentialType, _ := ssi.ParseURI("TestCredential")
	issuerID, _ := ssi.ParseURI("did:nuts:123")
	credentialOptions := vc.VerifiableCredential{
		Context: []ssi.URI{*credential.NutsContextURI},
		Type:    []ssi.URI{*credentialType},
		Issuer:  *issuerID,
		CredentialSubject: []interface{}{map[string]interface{}{
			"id": "did:nuts:456",
		}},
	}

	contextLoader, _ := signature.NewContextLoader(false)

	t.Run("ok - unpublished", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		kid := "did:nuts:123#abc"

		keyResolverMock := NewMockkeyResolver(ctrl)
		keyResolverMock.EXPECT().ResolveAssertionKey(gomock.Any()).Return(crypto.NewTestKey(kid), nil)
		mockStore := NewMockStore(ctrl)
		mockStore.EXPECT().StoreCredential(gomock.Any())
		sut := issuer{keyResolver: keyResolverMock, store: mockStore, contextLoader: contextLoader}

		result, err := sut.Issue(credentialOptions, false, true)
		assert.NoError(t, err)
		assert.Contains(t, result.Type, *credentialType, "expected vc to be of right type")
		proofs, _ := result.Proofs()
		assert.Equal(t, kid, proofs[0].VerificationMethod.String(), "expected to be signed with the kid")
		assert.Equal(t, issuerID.String(), result.Issuer.String(), "expected correct issuer")
		assert.Contains(t, result.Context, *credential.NutsContextURI)
		assert.Contains(t, result.Context, vc.VCContextV1URI())
	})

	t.Run("error - from used services", func(t *testing.T) {
		t.Run("could not store credential", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			kid := "did:nuts:123#abc"

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(gomock.Any()).Return(crypto.NewTestKey(kid), nil)
			mockStore := NewMockStore(ctrl)
			mockStore.EXPECT().StoreCredential(gomock.Any()).Return(errors.New("b00m!"))
			sut := issuer{keyResolver: keyResolverMock, store: mockStore, contextLoader: contextLoader}

			result, err := sut.Issue(credentialOptions, false, true)
			assert.EqualError(t, err, "unable to store the issued credential: b00m!")
			assert.Nil(t, result)
		})

		t.Run("could not publish credential", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			kid := "did:nuts:123#abc"

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(gomock.Any()).Return(crypto.NewTestKey(kid), nil)
			mockPublisher := NewMockPublisher(ctrl)
			mockPublisher.EXPECT().PublishCredential(gomock.Any(), true).Return(errors.New("b00m!"))
			mockStore := NewMockStore(ctrl)
			mockStore.EXPECT().StoreCredential(gomock.Any()).Return(nil)
			sut := issuer{keyResolver: keyResolverMock, store: mockStore, publisher: mockPublisher, contextLoader: contextLoader}

			result, err := sut.Issue(credentialOptions, true, true)
			assert.EqualError(t, err, "unable to publish the issued credential: b00m!")
			assert.Nil(t, result)
		})

		t.Run("validator fails (missing type)", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			sut := issuer{}

			credentialOptions := vc.VerifiableCredential{
				Type:   []ssi.URI{},
				Issuer: *issuerID,
			}

			result, err := sut.Issue(credentialOptions, true, true)
			assert.EqualError(t, err, "can only issue credential with 1 type")
			assert.Nil(t, result)

		})
	})
}

func TestNewIssuer(t *testing.T) {
	createdIssuer := NewIssuer(nil, nil, nil, nil, nil)
	assert.IsType(t, &issuer{}, createdIssuer)
}

func Test_issuer_buildRevocation(t *testing.T) {
	contextLoader, err := signature.NewContextLoader(false)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		kid := "did:nuts:123#abc"

		issuerDID, _ := did.ParseDID("did:nuts:123")
		keyResolverMock := NewMockkeyResolver(ctrl)
		keyResolverMock.EXPECT().ResolveAssertionKey(*issuerDID).Return(crypto.NewTestKey(kid), nil)

		credentialID, _ := ssi.ParseURI("did:nuts:123#" + uuid.NewString())

		sut := issuer{keyResolver: keyResolverMock, contextLoader: contextLoader}
		credentialToRevoke := vc.VerifiableCredential{
			Issuer: issuerDID.URI(),
			ID:     credentialID,
		}
		revocation, err := sut.buildRevocation(credentialToRevoke)
		assert.NoError(t, err)
		t.Logf("revocation %+v", revocation)
	})

	t.Run("canonicalization", func(t *testing.T) {

		revocationJSON := `
		{
			"@context": ["https://nuts.nl/credentials/v1"],
			"type": [ "CredentialRevocation" ],
			"subject": "did:nuts:123#5c9036ac-2e7a-4ae9-bc96-3b6269ecd27d",
			"date": "2022-02-17T14:32:19.290629+01:00",
			"issuer": "did:nuts:123"
		 }`

		revocationMap := map[string]interface{}{}
		json.Unmarshal([]byte(revocationJSON), &revocationMap)

		ldProof := signature.JSONWebSignature2020{ContextLoader: contextLoader}
		res, err := ldProof.CanonicalizeDocument(revocationMap)
		assert.NoError(t, err)
		expectedCanonicalForm := `_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://nuts.nl/credentials/v1#CredentialRevocation> .
_:c14n0 <https://nuts.nl/credentials/v1#date> "2022-02-17T14:32:19.290629+01:00"^^<xsd:dateTime> .
_:c14n0 <https://www.w3.org/2018/credentials#credentialSubject> <did:nuts:123#5c9036ac-2e7a-4ae9-bc96-3b6269ecd27d> .
_:c14n0 <https://www.w3.org/2018/credentials#issuer> <did:nuts:123> .
`

		assert.Equal(t, expectedCanonicalForm, string(res))
	})
}
