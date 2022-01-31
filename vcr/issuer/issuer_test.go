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
	"errors"
	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_issuer_buildVC(t *testing.T) {
	credentialType, _ := ssi.ParseURI("TestCredential")
	issuerID, _ := ssi.ParseURI("did:nuts:123")
	issuerDID, _ := did.ParseDID(issuerID.String())

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		kid := "did:nuts:123#abc"

		keyResolverMock := NewMockkeyResolver(ctrl)
		keyResolverMock.EXPECT().ResolveAssertionKey(gomock.Any()).Return(crypto.NewTestKey(kid), nil)
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
		result, err := sut.buildVC(credentialOptions)
		assert.NoError(t, err)
		assert.Contains(t, result.Type, *credentialType, "expected vc to be of right type")
		proofs, _ := result.Proofs()
		assert.Equal(t, kid, proofs[0].VerificationMethod.String(), "expected to be signed with the kid")
		assert.Equal(t, issuerID.String(), result.Issuer.String(), "expected correct issuer")
		assert.Contains(t, result.Context, *schemaOrgContext)
		assert.Contains(t, result.Context, vc.VCContextV1URI())
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

	t.Run("ok - unpublished", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		kid := "did:nuts:123#abc"

		keyResolverMock := NewMockkeyResolver(ctrl)
		keyResolverMock.EXPECT().ResolveAssertionKey(gomock.Any()).Return(crypto.NewTestKey(kid), nil)
		mockStore := NewMockStore(ctrl)
		mockStore.EXPECT().StoreCredential(gomock.Any())
		sut := issuer{keyResolver: keyResolverMock, store: mockStore}

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
			sut := issuer{keyResolver: keyResolverMock, store: mockStore}

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
			sut := issuer{keyResolver: keyResolverMock, store: mockStore, publisher: mockPublisher}

			result, err := sut.Issue(credentialOptions, true, true)
			assert.EqualError(t, err, "unable to publish the issued credential: b00m!")
			assert.Nil(t, result)
		})

		t.Run("invalid credential", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			kid := "did:nuts:123#abc"

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(gomock.Any()).Return(crypto.NewTestKey(kid), nil)
			sut := issuer{keyResolver: keyResolverMock}

			credentialType, _ := ssi.ParseURI("TestCredential")

			credentialOptions := vc.VerifiableCredential{
				Type:   []ssi.URI{*credentialType},
				Issuer: *issuerID,
			}

			result, err := sut.Issue(credentialOptions, true, true)
			assert.EqualError(t, err, "validation failed: nuts context is required")
			assert.Nil(t, result)

		})
	})
}

func TestNewIssuer(t *testing.T) {
	createdIssuer := NewIssuer(nil, nil, nil, nil)
	assert.IsType(t, &issuer{}, createdIssuer)
}
