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
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"path"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/trust"
	vcr "github.com/nuts-foundation/nuts-node/vcr/types"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

func Test_issuer_buildVC(t *testing.T) {
	credentialType := ssi.MustParseURI("TestCredential")
	issuerID := ssi.MustParseURI("did:nuts:123")
	issuerDID, _ := did.ParseDID(issuerID.String())

	t.Run("it issues a VC", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		kid := "did:nuts:123#abc"

		keyResolverMock := NewMockkeyResolver(ctrl)
		keyResolverMock.EXPECT().ResolveAssertionKey(gomock.Any()).Return(crypto.NewTestKey(kid), nil)
		jsonldManager := jsonld.NewTestJSONLDManager(t)
		sut := issuer{keyResolver: keyResolverMock, jsonldManager: jsonldManager}
		schemaOrgContext := ssi.MustParseURI("https://schema.org")

		issuance, err := time.Parse(time.RFC3339, "2022-01-02T12:00:00Z")
		assert.NoError(t, err)

		credentialOptions := vc.VerifiableCredential{
			Context:      []ssi.URI{schemaOrgContext},
			Type:         []ssi.URI{credentialType},
			Issuer:       issuerID,
			IssuanceDate: issuance,
			CredentialSubject: []interface{}{map[string]interface{}{
				"id": "did:nuts:456",
			}},
		}
		result, err := sut.buildVC(credentialOptions)
		if !assert.NoError(t, err) || !assert.NotNil(t, result) {
			return
		}
		assert.Contains(t, result.Type, credentialType, "expected vc to be of right type")
		proofs, _ := result.Proofs()
		assert.Equal(t, kid, proofs[0].VerificationMethod.String(), "expected to be signed with the kid")
		assert.Equal(t, issuerID.String(), result.Issuer.String(), "expected correct issuer")
		assert.Contains(t, result.Context, schemaOrgContext)
		assert.Contains(t, result.Context, vc.VCContextV1URI())
		assert.Equal(t, issuance, proofs[0].Created)
	})

	t.Run("it does not add the default context twice", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		kid := "did:nuts:123#abc"

		keyResolverMock := NewMockkeyResolver(ctrl)
		keyResolverMock.EXPECT().ResolveAssertionKey(gomock.Any()).Return(crypto.NewTestKey(kid), nil)
		jsonldManager := jsonld.NewTestJSONLDManager(t)
		sut := issuer{keyResolver: keyResolverMock, jsonldManager: jsonldManager}

		credentialOptions := vc.VerifiableCredential{
			Context:      []ssi.URI{vc.VCContextV1URI()},
			Type:         []ssi.URI{credentialType},
			Issuer:       issuerID,
			IssuanceDate: time.Now(),
		}

		result, err := sut.buildVC(credentialOptions)

		if !assert.NoError(t, err) || !assert.NotNil(t, result) {
			return
		}
		assert.Len(t, result.Context, 2)
		assert.Contains(t, result.Context, vc.VCContextV1URI())
	})

	t.Run("error - invalid params", func(t *testing.T) {
		t.Run("wrong amount of credential types", func(t *testing.T) {
			sut := issuer{}

			credentialOptions := vc.VerifiableCredential{
				Type: []ssi.URI{},
			}
			result, err := sut.buildVC(credentialOptions)

			assert.ErrorIs(t, err, core.InvalidInputError("can only issue credential with 1 type"))
			assert.Nil(t, result)
		})

		t.Run("missing issuer", func(t *testing.T) {
			sut := issuer{}

			credentialOptions := vc.VerifiableCredential{
				Type: []ssi.URI{credentialType},
			}
			result, err := sut.buildVC(credentialOptions)

			assert.ErrorIs(t, err, did.ErrInvalidDID)
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

			credentialOptions := vc.VerifiableCredential{
				Type:   []ssi.URI{credentialType},
				Issuer: issuerID,
			}
			_, err := sut.buildVC(credentialOptions)
			assert.EqualError(t, err, "failed to sign credential: could not resolve an assertionKey for issuer: b00m!")
		})

		t.Run("no DID Document for issuer", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(*issuerDID).Return(nil, vdr.ErrNotFound)
			sut := issuer{keyResolver: keyResolverMock}

			credentialOptions := vc.VerifiableCredential{
				Type:   []ssi.URI{credentialType},
				Issuer: issuerID,
			}
			_, err := sut.buildVC(credentialOptions)
			assert.ErrorIs(t, err, core.InvalidInputError("failed to sign credential: could not resolve an assertionKey for issuer: unable to find the DID document"))
		})

	})
}

func Test_issuer_Issue(t *testing.T) {
	credentialType := ssi.MustParseURI("HumanCredential")
	issuerID := ssi.MustParseURI("did:nuts:123")
	credentialOptions := vc.VerifiableCredential{
		Context: []ssi.URI{credential.NutsV1ContextURI},
		Type:    []ssi.URI{credentialType},
		Issuer:  issuerID,
		CredentialSubject: []interface{}{map[string]interface{}{
			"id": "did:nuts:456",
		}},
	}

	jsonldManager := jsonld.NewTestJSONLDManager(t)
	kid := "did:nuts:123#abc"

	t.Run("ok - unpublished", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		trustConfig := trust.NewConfig(path.Join(io.TestDirectory(t), "trust.config"))
		keyResolverMock := NewMockkeyResolver(ctrl)
		keyResolverMock.EXPECT().ResolveAssertionKey(gomock.Any()).Return(crypto.NewTestKey(kid), nil)
		mockStore := NewMockStore(ctrl)
		mockStore.EXPECT().StoreCredential(gomock.Any())
		sut := issuer{keyResolver: keyResolverMock, store: mockStore, jsonldManager: jsonldManager, trustConfig: trustConfig}

		result, err := sut.Issue(credentialOptions, false, true)
		if !assert.NoError(t, err) {
			return
		}
		assert.Contains(t, result.Type, credentialType, "expected vc to be of right type")
		proofs, _ := result.Proofs()
		assert.Equal(t, kid, proofs[0].VerificationMethod.String(), "expected to be signed with the kid")
		assert.Equal(t, issuerID.String(), result.Issuer.String(), "expected correct issuer")
		assert.Contains(t, result.Context, credential.NutsV1ContextURI)
		assert.Contains(t, result.Context, vc.VCContextV1URI())
		// Assert issuing a credential makes it trusted
		assert.True(t, trustConfig.IsTrusted(credentialType, result.Issuer))
	})

	t.Run("error - from used services", func(t *testing.T) {
		t.Run("could not store credential", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			trustConfig := trust.NewConfig(path.Join(io.TestDirectory(t), "trust.config"))
			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(gomock.Any()).Return(crypto.NewTestKey(kid), nil)
			mockStore := NewMockStore(ctrl)
			mockStore.EXPECT().StoreCredential(gomock.Any()).Return(errors.New("b00m!"))
			sut := issuer{keyResolver: keyResolverMock, store: mockStore, jsonldManager: jsonldManager, trustConfig: trustConfig}

			result, err := sut.Issue(credentialOptions, false, true)
			assert.EqualError(t, err, "unable to store the issued credential: b00m!")
			assert.Nil(t, result)
		})

		t.Run("could not publish credential", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			trustConfig := trust.NewConfig(path.Join(io.TestDirectory(t), "trust.config"))
			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(gomock.Any()).Return(crypto.NewTestKey(kid), nil)
			mockPublisher := NewMockPublisher(ctrl)
			mockPublisher.EXPECT().PublishCredential(gomock.Any(), true).Return(errors.New("b00m!"))
			mockStore := NewMockStore(ctrl)
			mockStore.EXPECT().StoreCredential(gomock.Any()).Return(nil)
			sut := issuer{keyResolver: keyResolverMock, store: mockStore, publisher: mockPublisher, jsonldManager: jsonldManager, trustConfig: trustConfig}

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
				Issuer: issuerID,
			}

			result, err := sut.Issue(credentialOptions, true, true)
			assert.EqualError(t, err, "can only issue credential with 1 type")
			assert.Nil(t, result)

		})

		t.Run("validator fails (undefined fields)", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(gomock.Any()).Return(crypto.NewTestKey(kid), nil)
			mockStore := NewMockStore(ctrl)
			sut := issuer{keyResolver: keyResolverMock, store: mockStore, jsonldManager: jsonldManager}

			invalidCred := credentialOptions
			invalidCred.CredentialSubject = []interface{}{
				map[string]interface{}{"foo": "bar"},
			}

			result, err := sut.Issue(invalidCred, true, true)
			assert.EqualError(t, err, "validation failed: invalid property: Dropping property that did not expand into an absolute IRI or keyword.")
			assert.Nil(t, result)

		})
	})
}

func TestNewIssuer(t *testing.T) {
	createdIssuer := NewIssuer(nil, nil, nil, nil, nil, nil)
	assert.IsType(t, &issuer{}, createdIssuer)
}

func Test_issuer_buildRevocation(t *testing.T) {
	jsonldManager := jsonld.NewTestJSONLDManager(t)

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		kid := "did:nuts:123#abc"

		issuerDID, _ := did.ParseDID("did:nuts:123")
		keyResolverMock := NewMockkeyResolver(ctrl)
		keyResolverMock.EXPECT().ResolveAssertionKey(*issuerDID).Return(crypto.NewTestKey(kid), nil)

		credentialID := ssi.MustParseURI("did:nuts:123#" + uuid.NewString())

		sut := issuer{keyResolver: keyResolverMock, jsonldManager: jsonldManager}
		credentialToRevoke := vc.VerifiableCredential{
			Issuer: issuerDID.URI(),
			ID:     &credentialID,
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

		ldProof := signature.JSONWebSignature2020{ContextLoader: jsonldManager.DocumentLoader()}
		res, err := ldProof.CanonicalizeDocument(revocationMap)
		assert.NoError(t, err)
		expectedCanonicalForm := `_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://nuts.nl/credentials/v1#CredentialRevocation> .
_:c14n0 <https://nuts.nl/credentials/v1#date> "2022-02-17T14:32:19.290629+01:00"^^<xsd:dateTime> .
_:c14n0 <https://www.w3.org/2018/credentials#credentialSubject> <did:nuts:123#5c9036ac-2e7a-4ae9-bc96-3b6269ecd27d> .
_:c14n0 <https://www.w3.org/2018/credentials#issuer> <did:nuts:123> .
`

		assert.Equal(t, expectedCanonicalForm, string(res))
	})

	t.Run("error - returned from used services", func(t *testing.T) {
		testVC := *credential.ValidNutsAuthorizationCredential()
		issuerDID := did.MustParseDID(testVC.Issuer.String())

		t.Run("no assertionKey for issuer", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(issuerDID).Return(nil, errors.New("b00m!"))
			sut := issuer{keyResolver: keyResolverMock}

			_, err := sut.buildRevocation(testVC)
			assert.EqualError(t, err, fmt.Sprintf("failed to revoke credential (%s): could not resolve an assertionKey for issuer: b00m!", testVC.ID))
		})

		t.Run("no DID Document for issuer", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(issuerDID).Return(nil, vdr.ErrNotFound)
			sut := issuer{keyResolver: keyResolverMock}

			_, err := sut.buildRevocation(testVC)
			assert.ErrorIs(t, err, core.InvalidInputError("failed to revoke credential: could not resolve an assertionKey for issuer: unable to find the DID document"))
		})

	})

}
func Test_issuer_Revoke(t *testing.T) {
	credentialID := "did:nuts:123#abc"
	credentialURI := ssi.MustParseURI(credentialID)
	issuerID := "did:nuts:123"
	issuerURI := ssi.MustParseURI(issuerID)
	issuerDID := did.MustParseDID(issuerID)
	jsonldManager := jsonld.NewTestJSONLDManager(t)
	kid := ssi.MustParseURI(issuerID + "#123")
	key := crypto.NewTestKey(kid.String())

	t.Run("for a known credential", func(t *testing.T) {
		credentialToRevoke := func() *vc.VerifiableCredential {
			return &vc.VerifiableCredential{
				ID:     &credentialURI,
				Issuer: issuerURI,
			}
		}

		storeWithActualCredential := func(c *gomock.Controller) *MockStore {
			store := NewMockStore(c)
			store.EXPECT().GetCredential(credentialURI).Return(credentialToRevoke(), nil)
			store.EXPECT().GetRevocation(credentialURI).Return(nil, ErrNotFound)
			return store
		}

		keyResolverWithKey := func(c *gomock.Controller) keyResolver {
			resolver := NewMockkeyResolver(c)
			resolver.EXPECT().ResolveAssertionKey(issuerDID).Return(key, nil)
			return resolver
		}

		t.Run("it revokes a credential", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			publisher := NewMockPublisher(ctrl)
			store := storeWithActualCredential(ctrl)
			publisher.EXPECT().PublishRevocation(gomock.Any()).Return(nil)
			store.EXPECT().StoreRevocation(gomock.Any()).Return(nil)

			sut := issuer{
				store:         store,
				keyResolver:   keyResolverWithKey(ctrl),
				jsonldManager: jsonldManager,
				publisher:     publisher,
			}

			revocation, err := sut.Revoke(credentialURI)
			assert.NoError(t, err)
			assert.NotNil(t, revocation)
			assert.Equal(t, issuerURI, revocation.Issuer)
			assert.Equal(t, credentialURI, revocation.Subject)

			// extract contexts as string into array since order of the revocation.Context is not guaranteed
			contexts := make([]string, len(revocation.Context))
			for i, val := range revocation.Context {
				contexts[i] = val.String()
			}
			assert.Contains(t, contexts, "https://nuts.nl/credentials/v1")
			assert.Contains(t, contexts, "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json")
			assert.Equal(t, kid, revocation.Proof.VerificationMethod)
		})

		t.Run("it handles a buildRevocation error", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// the credential does not contain a valid issuer:
			invalidCredential := vc.VerifiableCredential{}
			store := NewMockStore(ctrl)
			store.EXPECT().GetCredential(credentialURI).Return(&invalidCredential, nil)
			store.EXPECT().GetRevocation(credentialURI).Return(nil, ErrNotFound)

			sut := issuer{
				store: store,
			}
			revocation, err := sut.Revoke(credentialURI)
			assert.EqualError(t, err, "failed to extract issuer: invalid DID: input length is less than 7")
			assert.Nil(t, revocation)
		})

		t.Run("it handles a publication error", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			publisher := NewMockPublisher(ctrl)
			publisher.EXPECT().PublishRevocation(gomock.Any()).Return(errors.New("foo"))

			sut := issuer{
				store:         storeWithActualCredential(ctrl),
				keyResolver:   keyResolverWithKey(ctrl),
				jsonldManager: jsonldManager,
				publisher:     publisher,
			}

			revocation, err := sut.Revoke(credentialURI)
			assert.EqualError(t, err, "failed to publish revocation: foo")
			assert.Nil(t, revocation)
		})

		t.Run("it does not allow double revocation", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := storeWithActualCredential(ctrl)
			publisher := NewMockPublisher(ctrl)

			publisher.EXPECT().PublishRevocation(gomock.Any()).Return(nil)
			store.EXPECT().StoreRevocation(gomock.Any()).Return(nil)
			// 2nd revocation
			store.EXPECT().GetCredential(credentialURI).Return(credentialToRevoke(), nil)
			store.EXPECT().GetRevocation(credentialURI).Return(&credential.Revocation{}, nil)

			sut := issuer{
				store:         store,
				keyResolver:   keyResolverWithKey(ctrl),
				jsonldManager: jsonldManager,
				publisher:     publisher,
			}

			_, err := sut.Revoke(credentialURI)
			if !assert.NoError(t, err) {
				return
			}
			revocation, err := sut.Revoke(credentialURI)

			assert.ErrorIs(t, err, vcr.ErrRevoked)
			assert.Nil(t, revocation)
		})
	})

	t.Run("for an unknown credential", func(t *testing.T) {
		storeWithoutCredential := func(c *gomock.Controller) Store {
			store := NewMockStore(c)
			store.EXPECT().GetCredential(credentialURI).Return(nil, ErrNotFound)
			return store
		}

		t.Run("it returns an error", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			sut := issuer{
				store: storeWithoutCredential(ctrl),
			}

			revocation, err := sut.Revoke(credentialURI)
			assert.EqualError(t, err, "could not revoke (id=did:nuts:123#abc): not found")
			assert.Nil(t, revocation)
		})
	})
}

func TestIssuer_isRevoked(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	credentialID := "did:nuts:123#abc"
	credentialURI := ssi.MustParseURI(credentialID)

	store := NewMockStore(ctrl)

	sut := issuer{
		store: store,
	}

	t.Run("ok - no revocation", func(t *testing.T) {
		store.EXPECT().GetRevocation(credentialURI).Return(nil, ErrNotFound)

		isRevoked, err := sut.isRevoked(credentialURI)

		assert.NoError(t, err)
		assert.False(t, isRevoked)
	})
	t.Run("ok - revocation exists", func(t *testing.T) {
		store.EXPECT().GetRevocation(credentialURI).Return(&credential.Revocation{}, nil)

		isRevoked, err := sut.isRevoked(credentialURI)

		assert.NoError(t, err)
		assert.True(t, isRevoked)
	})
	t.Run("ok - multiple revocations exists", func(t *testing.T) {
		store.EXPECT().GetRevocation(credentialURI).Return(nil, ErrMultipleFound)

		isRevoked, err := sut.isRevoked(credentialURI)

		assert.NoError(t, err)
		assert.True(t, isRevoked)
	})
	t.Run("error", func(t *testing.T) {
		store.EXPECT().GetRevocation(credentialURI).Return(nil, errors.New("custom"))

		isRevoked, err := sut.isRevoked(credentialURI)

		assert.EqualError(t, err, "custom")
		assert.True(t, isRevoked)
	})

}
