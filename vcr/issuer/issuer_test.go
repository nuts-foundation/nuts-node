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
	"context"
	crypt "crypto"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/require"
	"path"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

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
)

func Test_issuer_buildVC(t *testing.T) {
	credentialType := ssi.MustParseURI("TestCredential")
	issuerID := ssi.MustParseURI("did:nuts:123")
	issuerDID, _ := did.ParseDID(issuerID.String())
	ctx := audit.TestContext()

	const kid = "did:nuts:123#abc"
	const subjectDID = "did:nuts:456"
	schemaOrgContext := ssi.MustParseURI("https://schema.org")
	issuance, err := time.Parse(time.RFC3339, "2022-01-02T12:00:00Z")
	require.NoError(t, err)

	expirationDate := issuance.Add(time.Hour)
	template := vc.VerifiableCredential{
		Context:        []ssi.URI{schemaOrgContext},
		Type:           []ssi.URI{credentialType},
		Issuer:         issuerID,
		IssuanceDate:   &issuance,
		ExpirationDate: &expirationDate,
		CredentialSubject: []interface{}{map[string]interface{}{
			"id": subjectDID,
		}},
	}
	keyStore := crypto.NewMemoryCryptoInstance()
	signingKey, err := keyStore.New(ctx, crypto.ECP256Key, func(key crypt.PublicKey) (string, error) {
		return kid, nil
	})
	require.NoError(t, err)

	t.Run("JSON-LD", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(signingKey, nil)
			jsonldManager := jsonld.NewTestJSONLDManager(t)
			sut := issuer{keyResolver: keyResolverMock, jsonldManager: jsonldManager, keyStore: keyStore}

			result, err := sut.buildVC(ctx, template, CredentialOptions{Format: JSONLDCredentialFormat})
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Contains(t, result.Type, credentialType, "expected vc to be of right type")
			assert.Equal(t, JSONLDCredentialFormat, result.Format())
			assert.Equal(t, issuerID.String(), result.Issuer.String(), "expected correct issuer")
			assert.Contains(t, result.Context, schemaOrgContext)
			assert.Contains(t, result.Context, vc.VCContextV1URI())
			// Assert proof
			proofs, _ := result.Proofs()
			assert.Equal(t, kid, proofs[0].VerificationMethod.String(), "expected to be signed with the kid")
			assert.Equal(t, issuance, proofs[0].Created)
		})
		t.Run("is default", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(signingKey, nil)
			jsonldManager := jsonld.NewTestJSONLDManager(t)
			sut := issuer{keyResolver: keyResolverMock, jsonldManager: jsonldManager, keyStore: keyStore}

			result, err := sut.buildVC(ctx, template, CredentialOptions{})
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, JSONLDCredentialFormat, result.Format())
		})
	})
	t.Run("JWT", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(signingKey, nil)
			jsonldManager := jsonld.NewTestJSONLDManager(t)
			sut := issuer{keyResolver: keyResolverMock, jsonldManager: jsonldManager, keyStore: keyStore}

			result, err := sut.buildVC(ctx, template, CredentialOptions{Format: JWTCredentialFormat})

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, JWTCredentialFormat, result.Format())
			assert.Contains(t, result.Type, credentialType, "expected vc to be of right type")
			assert.Contains(t, result.Context, schemaOrgContext)
			assert.Contains(t, result.Context, vc.VCContextV1URI())
			assert.Equal(t, template.IssuanceDate.Local(), result.IssuanceDate.Local())
			assert.Equal(t, template.ExpirationDate.Local(), result.ExpirationDate.Local())
			assert.Equal(t, template.Issuer, result.Issuer)
			assert.Equal(t, template.CredentialSubject, result.CredentialSubject)
			assert.Empty(t, result.Proof)
			// Assert JWT
			require.NotNil(t, result.JWT())
			assert.Equal(t, subjectDID, result.JWT().Subject())
			assert.Equal(t, *result.IssuanceDate, result.JWT().NotBefore())
			assert.Equal(t, *result.ExpirationDate, result.JWT().Expiration())
			assert.Equal(t, result.ID.String(), result.JWT().JwtID())
		})
	})

	t.Run("it does not add the default context twice", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		keyResolverMock := NewMockkeyResolver(ctrl)
		keyResolverMock.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(signingKey, nil)
		jsonldManager := jsonld.NewTestJSONLDManager(t)
		sut := issuer{keyResolver: keyResolverMock, jsonldManager: jsonldManager, keyStore: keyStore}

		issuanceDate := time.Now()
		template := vc.VerifiableCredential{
			Context:      []ssi.URI{vc.VCContextV1URI()},
			Type:         []ssi.URI{credentialType},
			Issuer:       issuerID,
			IssuanceDate: &issuanceDate,
		}

		result, err := sut.buildVC(ctx, template, CredentialOptions{})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.Context, 2)
		assert.Contains(t, result.Context, vc.VCContextV1URI())
	})

	t.Run("error - invalid params", func(t *testing.T) {
		t.Run("wrong amount of credential types", func(t *testing.T) {
			sut := issuer{}

			template := vc.VerifiableCredential{
				Type: []ssi.URI{},
			}
			result, err := sut.buildVC(ctx, template, CredentialOptions{})

			assert.ErrorIs(t, err, core.InvalidInputError("can only issue credential with 1 type"))
			assert.Nil(t, result)
		})

		t.Run("missing issuer", func(t *testing.T) {
			sut := issuer{}

			template := vc.VerifiableCredential{
				Type: []ssi.URI{credentialType},
			}
			result, err := sut.buildVC(ctx, template, CredentialOptions{})

			assert.ErrorIs(t, err, did.ErrInvalidDID)
			assert.Nil(t, result)
		})
		t.Run("unsupported proof format", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(signingKey, nil)
			jsonldManager := jsonld.NewTestJSONLDManager(t)
			sut := issuer{keyResolver: keyResolverMock, jsonldManager: jsonldManager, keyStore: keyStore}

			result, err := sut.buildVC(ctx, template, CredentialOptions{Format: "paper"})

			assert.EqualError(t, err, "unsupported credential proof format")
			assert.Nil(t, result)
		})
	})

	t.Run("error - returned from used services", func(t *testing.T) {
		t.Run("no assertionKey for issuer", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(ctx, *issuerDID).Return(nil, errors.New("b00m!"))
			sut := issuer{keyResolver: keyResolverMock}

			template := vc.VerifiableCredential{
				Type:   []ssi.URI{credentialType},
				Issuer: issuerID,
			}
			_, err := sut.buildVC(ctx, template, CredentialOptions{})
			assert.EqualError(t, err, "failed to sign credential: could not resolve an assertionKey for issuer: b00m!")
		})

		t.Run("no DID Document for issuer", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(ctx, *issuerDID).Return(nil, resolver.ErrNotFound)
			sut := issuer{keyResolver: keyResolverMock}

			template := vc.VerifiableCredential{
				Type:   []ssi.URI{credentialType},
				Issuer: issuerID,
			}
			_, err := sut.buildVC(ctx, template, CredentialOptions{})
			assert.ErrorIs(t, err, core.InvalidInputError("failed to sign credential: could not resolve an assertionKey for issuer: unable to find the DID document"))
		})
	})
}

func Test_issuer_Issue(t *testing.T) {
	credentialType := ssi.MustParseURI("HumanCredential")
	issuerDID := did.MustParseDID("did:nuts:123")
	issuerKeyID := issuerDID.String() + "#abc"
	holderDID := did.MustParseDID("did:nuts:456")

	template := vc.VerifiableCredential{
		Context: []ssi.URI{credential.NutsV1ContextURI},
		Type:    []ssi.URI{credentialType},
		Issuer:  issuerDID.URI(),
		CredentialSubject: []interface{}{map[string]interface{}{
			"id": holderDID.String(),
		}},
	}
	ctx := audit.TestContext()
	jsonldManager := jsonld.NewTestJSONLDManager(t)

	t.Run("ok - unpublished", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		trustConfig := trust.NewConfig(path.Join(io.TestDirectory(t), "trust.config"))
		keyResolverMock := NewMockkeyResolver(ctrl)
		keyResolverMock.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(crypto.NewTestKey(issuerKeyID), nil)
		mockStore := NewMockStore(ctrl)
		mockStore.EXPECT().StoreCredential(gomock.Any())
		sut := issuer{
			keyResolver: keyResolverMock, store: mockStore,
			jsonldManager: jsonldManager, trustConfig: trustConfig,
			keyStore: crypto.NewMemoryCryptoInstance(),
		}

		result, err := sut.Issue(ctx, template, CredentialOptions{
			Publish: false,
			Public:  true,
		})
		require.NoError(t, err)
		assert.Contains(t, result.Type, credentialType, "expected vc to be of right type")
		proofs, _ := result.Proofs()
		assert.Equal(t, issuerKeyID, proofs[0].VerificationMethod.String(), "expected to be signed with the kid")
		assert.Equal(t, issuerDID.String(), result.Issuer.String(), "expected correct issuer")
		assert.Contains(t, result.Context, credential.NutsV1ContextURI)
		assert.Contains(t, result.Context, vc.VCContextV1URI())
		// Assert issuing a credential makes it trusted
		assert.True(t, trustConfig.IsTrusted(credentialType, result.Issuer))
	})

	t.Run("publishing JWT VCs is disallowed", func(t *testing.T) {
		sut := issuer{}

		result, err := sut.Issue(ctx, template, CredentialOptions{
			Publish: true,
			Public:  true,
			Format:  JWTCredentialFormat,
		})
		require.EqualError(t, err, "publishing VC JWTs is not supported")
		assert.Nil(t, result)
	})

	t.Run("OpenID4VCI", func(t *testing.T) {
		const walletIdentifier = "http://example.com/wallet"
		t.Run("ok - publish over OpenID4VCI fails - fallback to network", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			publisher := NewMockPublisher(ctrl)
			publisher.EXPECT().PublishCredential(gomock.Any(), gomock.Any(), gomock.Any())
			walletResolver := openid4vci.NewMockIdentifierResolver(ctrl)
			walletResolver.EXPECT().Resolve(gomock.Any()).Return(walletIdentifier, nil)
			openidHandler := NewMockOpenIDHandler(ctrl)
			openidHandler.EXPECT().OfferCredential(gomock.Any(), gomock.Any(), walletIdentifier).Return(errors.New("failed"))
			keyResolver := NewMockkeyResolver(ctrl)
			keyResolver.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(crypto.NewTestKey(issuerKeyID), nil)
			store := NewMockStore(ctrl)
			store.EXPECT().StoreCredential(gomock.Any())
			sut := issuer{
				keyResolver:   keyResolver,
				store:         store,
				jsonldManager: jsonldManager,
				trustConfig:   trust.NewConfig(path.Join(io.TestDirectory(t), "trust.config")),
				keyStore:      crypto.NewMemoryCryptoInstance(),
				openidHandlerFn: func(_ context.Context, id did.DID) (OpenIDHandler, error) {
					if id.Equals(issuerDID) {
						return openidHandler, nil
					}
					return nil, nil
				},
				walletResolver:   walletResolver,
				networkPublisher: publisher,
			}

			result, err := sut.Issue(ctx, template, CredentialOptions{
				Publish: true,
				Public:  false,
			})

			require.NoError(t, err)
			assert.NotNil(t, result)
		})
		t.Run("ok - OpenID4VCI not enabled - fallback to network", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			publisher := NewMockPublisher(ctrl)
			publisher.EXPECT().PublishCredential(gomock.Any(), gomock.Any(), gomock.Any())
			keyResolver := NewMockkeyResolver(ctrl)
			keyResolver.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(crypto.NewTestKey(issuerKeyID), nil)
			store := NewMockStore(ctrl)
			store.EXPECT().StoreCredential(gomock.Any())
			sut := issuer{
				keyResolver:      keyResolver,
				store:            store,
				jsonldManager:    jsonldManager,
				trustConfig:      trust.NewConfig(path.Join(io.TestDirectory(t), "trust.config")),
				keyStore:         crypto.NewMemoryCryptoInstance(),
				networkPublisher: publisher,
			}

			result, err := sut.Issue(ctx, template, CredentialOptions{
				Publish: true,
				Public:  false,
			})

			require.NoError(t, err)
			assert.NotNil(t, result)
		})
		t.Run("ok - OpenID4VCI not enabled for holder DID - fallback to network", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			walletResolver := openid4vci.NewMockIdentifierResolver(ctrl)
			walletResolver.EXPECT().Resolve(holderDID).AnyTimes().Return(walletIdentifier, nil)
			publisher := NewMockPublisher(ctrl)
			publisher.EXPECT().PublishCredential(gomock.Any(), gomock.Any(), gomock.Any())
			keyResolver := NewMockkeyResolver(ctrl)
			keyResolver.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(crypto.NewTestKey(issuerKeyID), nil)
			store := NewMockStore(ctrl)
			store.EXPECT().StoreCredential(gomock.Any())
			sut := issuer{
				keyResolver:      keyResolver,
				store:            store,
				jsonldManager:    jsonldManager,
				trustConfig:      trust.NewConfig(path.Join(io.TestDirectory(t), "trust.config")),
				keyStore:         crypto.NewMemoryCryptoInstance(),
				walletResolver:   walletResolver,
				networkPublisher: publisher,
			}

			result, err := sut.Issue(ctx, template, CredentialOptions{
				Publish: true,
				Public:  false,
			})

			require.NoError(t, err)
			assert.NotNil(t, result)
		})
		t.Run("ok - publish over OpenID4VCI", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			walletResolver := openid4vci.NewMockIdentifierResolver(ctrl)
			walletResolver.EXPECT().Resolve(holderDID).AnyTimes().Return(walletIdentifier, nil)
			openidIssuer := NewMockOpenIDHandler(ctrl)
			openidIssuer.EXPECT().OfferCredential(gomock.Any(), gomock.Any(), walletIdentifier)
			vcrStore := vcr.NewMockWriter(ctrl)
			vcrStore.EXPECT().StoreCredential(gomock.Any(), gomock.Any())
			keyResolver := NewMockkeyResolver(ctrl)
			keyResolver.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(crypto.NewTestKey(issuerKeyID), nil)
			store := NewMockStore(ctrl)
			store.EXPECT().StoreCredential(gomock.Any())
			sut := issuer{
				keyResolver:    keyResolver,
				store:          store,
				jsonldManager:  jsonldManager,
				trustConfig:    trust.NewConfig(path.Join(io.TestDirectory(t), "trust.config")),
				keyStore:       crypto.NewMemoryCryptoInstance(),
				walletResolver: walletResolver,
				openidHandlerFn: func(ctx context.Context, id did.DID) (OpenIDHandler, error) {
					if id.Equals(issuerDID) {
						return openidIssuer, nil
					}
					return nil, nil
				},
				vcrStore: vcrStore,
			}

			result, err := sut.Issue(ctx, template, CredentialOptions{
				Publish: true,
				Public:  false,
			})

			require.NoError(t, err)
			assert.NotNil(t, result)
		})
	})

	t.Run("error - from used services", func(t *testing.T) {
		t.Run("could not store credential", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			trustConfig := trust.NewConfig(path.Join(io.TestDirectory(t), "trust.config"))
			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(crypto.NewTestKey(issuerKeyID), nil)
			mockStore := NewMockStore(ctrl)
			mockStore.EXPECT().StoreCredential(gomock.Any()).Return(errors.New("b00m!"))
			sut := issuer{
				keyResolver: keyResolverMock, store: mockStore,
				jsonldManager: jsonldManager, trustConfig: trustConfig,
				keyStore: crypto.NewMemoryCryptoInstance(),
			}

			result, err := sut.Issue(ctx, template, CredentialOptions{
				Publish: false,
				Public:  true,
			})
			assert.EqualError(t, err, "unable to store the issued credential: b00m!")
			assert.Nil(t, result)
		})

		t.Run("could not publish credential", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			trustConfig := trust.NewConfig(path.Join(io.TestDirectory(t), "trust.config"))
			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(crypto.NewTestKey(issuerKeyID), nil)
			mockPublisher := NewMockPublisher(ctrl)
			mockPublisher.EXPECT().PublishCredential(gomock.Any(), gomock.Any(), true).Return(errors.New("b00m!"))
			mockStore := NewMockStore(ctrl)
			mockStore.EXPECT().StoreCredential(gomock.Any()).Return(nil)
			sut := issuer{keyResolver: keyResolverMock, store: mockStore, networkPublisher: mockPublisher,
				jsonldManager: jsonldManager, trustConfig: trustConfig,
				keyStore: crypto.NewMemoryCryptoInstance(),
			}

			result, err := sut.Issue(ctx, template, CredentialOptions{
				Publish: true,
				Public:  true,
			})
			assert.EqualError(t, err, "unable to publish the issued credential: b00m!")
			assert.Nil(t, result)
		})

		t.Run("validator fails (missing type)", func(t *testing.T) {
			sut := issuer{}

			credentialOptions := vc.VerifiableCredential{
				Type:   []ssi.URI{},
				Issuer: issuerDID.URI(),
			}

			result, err := sut.Issue(ctx, credentialOptions, CredentialOptions{
				Publish: true,
				Public:  true,
			})
			assert.EqualError(t, err, "can only issue credential with 1 type")
			assert.Nil(t, result)

		})

		t.Run("validator fails (undefined fields)", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(crypto.NewTestKey(issuerKeyID), nil)
			mockStore := NewMockStore(ctrl)
			sut := issuer{keyResolver: keyResolverMock, store: mockStore, jsonldManager: jsonldManager, keyStore: crypto.NewMemoryCryptoInstance()}

			invalidCred := template
			invalidCred.CredentialSubject = []interface{}{
				map[string]interface{}{"foo": "bar"},
			}

			result, err := sut.Issue(ctx, invalidCred, CredentialOptions{
				Publish: true,
				Public:  true,
			})
			assert.EqualError(t, err, "validation failed: invalid property: Dropping property that did not expand into an absolute IRI or keyword.")
			assert.Nil(t, result)
		})
	})
}

func TestNewIssuer(t *testing.T) {
	createdIssuer := NewIssuer(nil, nil, nil, nil, nil, nil, nil, nil)
	assert.IsType(t, &issuer{}, createdIssuer)
}

func Test_issuer_buildRevocation(t *testing.T) {
	jsonldManager := jsonld.NewTestJSONLDManager(t)
	ctx := audit.TestContext()

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		kid := "did:nuts:123#abc"

		issuerDID, _ := did.ParseDID("did:nuts:123")
		keyResolverMock := NewMockkeyResolver(ctrl)
		keyResolverMock.EXPECT().ResolveAssertionKey(ctx, *issuerDID).Return(crypto.NewTestKey(kid), nil)

		credentialID := ssi.MustParseURI("did:nuts:123#" + uuid.NewString())

		sut := issuer{keyResolver: keyResolverMock, jsonldManager: jsonldManager, keyStore: crypto.NewMemoryCryptoInstance()}
		credentialToRevoke := vc.VerifiableCredential{
			Issuer: issuerDID.URI(),
			ID:     &credentialID,
		}
		revocation, err := sut.buildRevocation(ctx, *credentialToRevoke.ID)
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

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(ctx, issuerDID).Return(nil, errors.New("b00m!"))
			sut := issuer{keyResolver: keyResolverMock}

			_, err := sut.buildRevocation(ctx, *testVC.ID)
			assert.EqualError(t, err, fmt.Sprintf("failed to revoke credential (%s): could not resolve an assertionKey for issuer: b00m!", testVC.ID))
		})

		t.Run("no DID Document for issuer", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(ctx, issuerDID).Return(nil, resolver.ErrNotFound)
			sut := issuer{keyResolver: keyResolverMock}

			_, err := sut.buildRevocation(ctx, *testVC.ID)
			assert.ErrorIs(t, err, core.InvalidInputError("failed to revoke credential: could not resolve an assertionKey for issuer: unable to find the DID document"))
		})
	})
}
func Test_issuer_Revoke(t *testing.T) {
	credentialID := "did:nuts:123#38E90E8C-F7E5-4333-B63A-F9DD155A0272"
	credentialURI := ssi.MustParseURI(credentialID)
	issuerID := "did:nuts:123"
	issuerURI := ssi.MustParseURI(issuerID)
	issuerDID := did.MustParseDID(issuerID)
	jsonldManager := jsonld.NewTestJSONLDManager(t)
	kid := ssi.MustParseURI(issuerID + "#123")
	key := crypto.NewTestKey(kid.String())
	ctx := audit.TestContext()

	t.Run("for a known credential", func(t *testing.T) {
		storeWithActualCredential := func(c *gomock.Controller) *MockStore {
			store := NewMockStore(c)
			store.EXPECT().GetRevocation(credentialURI).Return(nil, vcr.ErrNotFound)
			return store
		}

		keyResolverWithKey := func(c *gomock.Controller) keyResolver {
			resolver := NewMockkeyResolver(c)
			resolver.EXPECT().ResolveAssertionKey(ctx, issuerDID).Return(key, nil)
			return resolver
		}

		t.Run("it revokes a credential", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			publisher := NewMockPublisher(ctrl)
			store := storeWithActualCredential(ctrl)
			publisher.EXPECT().PublishRevocation(gomock.Any(), gomock.Any()).Return(nil)
			store.EXPECT().StoreRevocation(gomock.Any()).Return(nil)

			sut := issuer{
				store:            store,
				keyResolver:      keyResolverWithKey(ctrl),
				jsonldManager:    jsonldManager,
				networkPublisher: publisher,
				keyStore:         crypto.NewMemoryCryptoInstance(),
			}

			revocation, err := sut.Revoke(ctx, credentialURI)
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

		t.Run("error - unable to check revocation status", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			// GetRevocation fails
			store := NewMockStore(ctrl)
			store.EXPECT().GetRevocation(credentialURI).Return(nil, errors.New("oops"))

			sut := issuer{
				store: store,
			}
			revocation, err := sut.Revoke(ctx, credentialURI)
			assert.EqualError(t, err, "error while checking revocation status: oops")
			assert.Nil(t, revocation)
		})

		t.Run("error - invalid credential ID (fragment is not a UUID)", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := NewMockStore(ctrl)
			store.EXPECT().GetRevocation(gomock.Any()).Return(nil, vcr.ErrNotFound)

			sut := issuer{
				store: store,
			}
			revocation, err := sut.Revoke(ctx, ssi.MustParseURI("did:nuts:123#invalid"))
			assert.EqualError(t, err, "invalid credential ID")
			assert.Nil(t, revocation)
		})

		t.Run("error - invalid DID", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := NewMockStore(ctrl)
			store.EXPECT().GetRevocation(gomock.Any()).Return(nil, vcr.ErrNotFound)

			sut := issuer{
				store: store,
			}
			revocation, err := sut.Revoke(ctx, ssi.MustParseURI("a#38E90E8C-F7E5-4333-B63A-F9DD155A0272"))
			assert.EqualError(t, err, "failed to extract issuer: invalid DID: DID must start with 'did:'")
			assert.Nil(t, revocation)
		})

		t.Run("it handles a publication error", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			publisher := NewMockPublisher(ctrl)
			publisher.EXPECT().PublishRevocation(gomock.Any(), gomock.Any()).Return(errors.New("foo"))

			sut := issuer{
				store:            storeWithActualCredential(ctrl),
				keyResolver:      keyResolverWithKey(ctrl),
				jsonldManager:    jsonldManager,
				networkPublisher: publisher,
				keyStore:         crypto.NewMemoryCryptoInstance(),
			}

			revocation, err := sut.Revoke(ctx, credentialURI)
			assert.EqualError(t, err, "failed to publish revocation: foo")
			assert.Nil(t, revocation)
		})

		t.Run("it does not allow double revocation", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			store := storeWithActualCredential(ctrl)
			publisher := NewMockPublisher(ctrl)

			publisher.EXPECT().PublishRevocation(gomock.Any(), gomock.Any()).Return(nil)
			store.EXPECT().StoreRevocation(gomock.Any()).Return(nil)
			// 2nd revocation
			store.EXPECT().GetRevocation(credentialURI).Return(&credential.Revocation{}, nil)

			sut := issuer{
				store:            store,
				keyResolver:      keyResolverWithKey(ctrl),
				jsonldManager:    jsonldManager,
				networkPublisher: publisher,
				keyStore:         crypto.NewMemoryCryptoInstance(),
			}

			_, err := sut.Revoke(ctx, credentialURI)
			require.NoError(t, err)
			revocation, err := sut.Revoke(ctx, credentialURI)

			assert.ErrorIs(t, err, vcr.ErrRevoked)
			assert.Nil(t, revocation)
		})
	})
}

func TestIssuer_isRevoked(t *testing.T) {
	ctrl := gomock.NewController(t)

	credentialID := "did:nuts:123#abc"
	credentialURI := ssi.MustParseURI(credentialID)

	store := NewMockStore(ctrl)

	sut := issuer{
		store: store,
	}

	t.Run("ok - no revocation", func(t *testing.T) {
		store.EXPECT().GetRevocation(credentialURI).Return(nil, vcr.ErrNotFound)

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
		store.EXPECT().GetRevocation(credentialURI).Return(nil, vcr.ErrMultipleFound)

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
