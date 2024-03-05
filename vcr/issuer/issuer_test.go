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
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/nuts-foundation/nuts-node/vcr/revocation"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
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

var nutsIssuerDID = did.MustParseDID("did:nuts:123")
var webIssuerDID = did.MustParseDID("did:web:example.cpom")

func Test_issuer_buildAndSignVC(t *testing.T) {
	credentialType := ssi.MustParseURI("TestCredential")
	issuerID := ssi.MustParseURI("did:nuts:123")
	issuerDID, _ := did.ParseDID(issuerID.String())
	ctx := audit.TestContext()

	const kid = "did:nuts:123#abc"
	const subjectDID = "did:nuts:456"
	schemaOrgContext := ssi.MustParseURI("https://schema.org")
	issuance, err := time.Parse(time.RFC3339, "2022-01-02T12:00:00Z")
	require.NoError(t, err)
	TimeFunc = func() time.Time { return issuance }
	defer func() { TimeFunc = time.Now }()

	expirationDate := issuance.Add(time.Hour)
	template := vc.VerifiableCredential{
		Context:        []ssi.URI{schemaOrgContext},
		Type:           []ssi.URI{credentialType},
		Issuer:         issuerID,
		ExpirationDate: &expirationDate,
		CredentialSubject: []interface{}{map[string]interface{}{
			"id": subjectDID,
		}},
	}
	keyStore := crypto.NewMemoryCryptoInstance()
	signingKey, err := keyStore.New(ctx, func(key crypt.PublicKey) (string, error) {
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

			result, err := sut.buildAndSignVC(ctx, template, CredentialOptions{Format: vc.JSONLDCredentialProofFormat})
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Contains(t, result.Type, credentialType, "expected vc to be of right type")
			assert.Equal(t, vc.JSONLDCredentialProofFormat, result.Format())
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

			result, err := sut.buildAndSignVC(ctx, template, CredentialOptions{})
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, vc.JSONLDCredentialProofFormat, result.Format())
		})
	})
	t.Run("JWT", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(signingKey, nil)
			jsonldManager := jsonld.NewTestJSONLDManager(t)
			sut := issuer{keyResolver: keyResolverMock, jsonldManager: jsonldManager, keyStore: keyStore}

			result, err := sut.buildAndSignVC(ctx, template, CredentialOptions{Format: vc.JWTCredentialProofFormat})

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, vc.JWTCredentialProofFormat, result.Format())
			assert.Contains(t, result.Type, credentialType, "expected vc to be of right type")
			assert.Contains(t, result.Context, schemaOrgContext)
			assert.Contains(t, result.Context, vc.VCContextV1URI())
			assert.Equal(t, issuance.Local(), result.IssuanceDate.Local())
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
	t.Run("credentialStatus", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			issuerDID := did.MustParseDID("did:web:example.com:iam:123")
			slTemplate := template
			slTemplate.Issuer = issuerDID.URI() // does not overwrite template

			ctrl := gomock.NewController(t)
			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(signingKey, nil)
			jsonldManager := jsonld.NewTestJSONLDManager(t)
			sut := issuer{keyResolver: keyResolverMock, jsonldManager: jsonldManager, keyStore: keyStore, statusListStore: NewTestStatusListStore(t, issuerDID)}

			result, err := sut.buildAndSignVC(ctx, slTemplate, CredentialOptions{WithStatusListRevocation: true})

			// only check fields relevant to credential status
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Contains(t, result.Context, revocation.StatusList2021ContextURI)

			statuses, err := result.CredentialStatuses()
			require.NoError(t, err)
			require.Len(t, statuses, 1)
			assert.Equal(t, revocation.StatusList2021EntryType, statuses[0].Type)
		})
		t.Run("error - did:nuts", func(t *testing.T) {
			sut := issuer{keyStore: keyStore, statusListStore: NewTestStatusListStore(t)}

			result, err := sut.buildAndSignVC(ctx, template, CredentialOptions{WithStatusListRevocation: true})

			// only check fields relevant to credential status
			assert.ErrorContains(t, err, "unsupported DID method: nuts")
			assert.Nil(t, result)
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

		result, err := sut.buildAndSignVC(ctx, template, CredentialOptions{})

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
			result, err := sut.buildAndSignVC(ctx, template, CredentialOptions{})

			assert.ErrorIs(t, err, core.InvalidInputError("can only issue credential with 1 type"))
			assert.Nil(t, result)
		})

		t.Run("missing issuer", func(t *testing.T) {
			sut := issuer{}

			template := vc.VerifiableCredential{
				Type: []ssi.URI{credentialType},
			}
			result, err := sut.buildAndSignVC(ctx, template, CredentialOptions{})

			assert.ErrorIs(t, err, did.ErrInvalidDID)
			assert.Nil(t, result)
		})
		t.Run("unsupported proof format", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolverMock := NewMockkeyResolver(ctrl)
			keyResolverMock.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(signingKey, nil)
			jsonldManager := jsonld.NewTestJSONLDManager(t)
			sut := issuer{keyResolver: keyResolverMock, jsonldManager: jsonldManager, keyStore: keyStore}

			result, err := sut.buildAndSignVC(ctx, template, CredentialOptions{Format: "paper"})

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
			_, err := sut.buildAndSignVC(ctx, template, CredentialOptions{})
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
			_, err := sut.buildAndSignVC(ctx, template, CredentialOptions{})
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
			Format:  vc.JWTCredentialProofFormat,
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
			assert.EqualError(t, err, "jsonld: invalid property: Dropping property that did not expand into an absolute IRI or keyword.")
			assert.Nil(t, result)
		})
	})
}

func TestNewIssuer(t *testing.T) {
	createdIssuer := NewIssuer(nil, nil, nil, nil, nil, nil, nil, nil, &revocation.StatusList2021{})
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
		testVC := test.ValidNutsAuthorizationCredential(t)
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
func Test_issuer_revokeNetwork(t *testing.T) {
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

func TestIssuer_revokeStatusList(t *testing.T) {
	issuerDID := did.MustParseDID("did:web:example.com:iam:123")
	storeWithCred := func(c *gomock.Controller, entry revocation.StatusList2021Entry) (*MockStore, ssi.URI) {
		credentialID := ssi.MustParseURI(issuerDID.String() + "#identifier")
		cred := &vc.VerifiableCredential{
			ID:               &credentialID,
			Issuer:           ssi.MustParseURI(issuerDID.String()),
			CredentialStatus: []any{entry},
		}
		store := NewMockStore(c)
		store.EXPECT().GetCredential(*cred.ID).Return(cred, nil).MinTimes(1)
		return store, credentialID
	}

	t.Run("ok", func(t *testing.T) {
		status := NewTestStatusListStore(t, issuerDID)
		entry, err := status.Create(context.Background(), issuerDID, revocation.StatusPurposeRevocation)
		require.NoError(t, err)
		issuerStore, credentialID := storeWithCred(gomock.NewController(t), *entry)
		sut := issuer{
			store:           issuerStore,
			statusListStore: status,
		}

		revCred, err := sut.Revoke(context.Background(), credentialID)

		assert.NoError(t, err)
		assert.Nil(t, revCred)
	})
	t.Run("error - double revocation", func(t *testing.T) {
		status := NewTestStatusListStore(t, issuerDID)
		entry, err := status.Create(context.Background(), issuerDID, revocation.StatusPurposeRevocation)
		require.NoError(t, err)
		issuerStore, credentialID := storeWithCred(gomock.NewController(t), *entry)
		sut := issuer{
			store:           issuerStore,
			statusListStore: status,
		}

		_, err = sut.Revoke(context.Background(), credentialID)
		require.NoError(t, err)
		_, err = sut.Revoke(context.Background(), credentialID)

		assert.ErrorIs(t, err, vcr.ErrRevoked)
	})
	t.Run("error - credential not found", func(t *testing.T) {
		store := NewMockStore(gomock.NewController(t))
		store.EXPECT().GetCredential(gomock.Any()).Return(nil, vcr.ErrNotFound)
		sut := issuer{store: store}

		result, err := sut.Revoke(context.Background(), ssi.MustParseURI("did:web:example.com:iam#not-found"))

		assert.ErrorIs(t, err, vcr.ErrNotFound)
		assert.Nil(t, result)
	})
	t.Run("error - statuslist credential not found", func(t *testing.T) {
		status := NewTestStatusListStore(t, issuerDID)
		entry, err := status.Create(context.Background(), issuerDID, revocation.StatusPurposeRevocation)
		require.NoError(t, err)
		entry.StatusListCredential = "unknown status list"
		issuerStore, credentialID := storeWithCred(gomock.NewController(t), *entry)
		sut := issuer{
			store:           issuerStore,
			statusListStore: status,
		}

		_, err = sut.Revoke(context.Background(), credentialID)

		assert.ErrorIs(t, err, vcr.ErrNotFound)
	})
	t.Run("error - invalid credentialStatus", func(t *testing.T) {
	})
	t.Run("error - no revokable credential status", func(t *testing.T) {
		issuerStore, credentialID := storeWithCred(gomock.NewController(t), revocation.StatusList2021Entry{
			Type:          revocation.StatusList2021EntryType,
			StatusPurpose: "not revocation",
		})
		sut := issuer{store: issuerStore}

		_, err := sut.Revoke(context.Background(), credentialID)

		assert.ErrorIs(t, err, vcr.ErrStatusNotFound)
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

func TestIssuer_StatusList(t *testing.T) {
	issuerDID := did.MustParseDID("did:web:example.com:iam:123")
	issuerURL, err := didweb.DIDToURL(issuerDID)
	require.NoError(t, err)

	ctx := audit.TestContext()
	const kid = "did:web:example.com:iam:123#abc"
	keyStore := crypto.NewMemoryCryptoInstance()
	signingKey, err := keyStore.New(ctx, func(key crypt.PublicKey) (string, error) {
		return kid, nil
	})
	require.NoError(t, err)

	jsonldManager := jsonld.NewTestJSONLDManager(t)
	trustConfig := trust.NewConfig(path.Join(io.TestDirectory(t), "trust.config"))
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		keyResolverMock := NewMockkeyResolver(ctrl)
		keyResolverMock.EXPECT().ResolveAssertionKey(ctx, gomock.Any()).Return(signingKey, nil)
		sut := issuer{
			keyResolver:     keyResolverMock,
			jsonldManager:   jsonldManager,
			keyStore:        keyStore,
			trustConfig:     trustConfig,
			statusListStore: NewTestStatusListStore(t, issuerDID),
		}
		sut.statusListStore.(*revocation.StatusList2021).Sign = sut.signVC
		_, err = sut.statusListStore.Create(ctx, issuerDID, revocation.StatusPurposeRevocation)
		require.NoError(t, err)

		result, err := sut.StatusList(ctx, issuerDID, 1)

		// credential
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Contains(t, result.Context, revocation.StatusList2021ContextURI)
		assert.Equal(t, result.Issuer.String(), issuerDID.String())
		assert.True(t, result.IsType(ssi.MustParseURI(revocation.StatusList2021CredentialType)))
		assert.Nil(t, result.IssuanceDate)
		assert.Nil(t, result.ExpirationDate)
		assert.InDelta(t, result.ValidFrom.Unix(), time.Now().Unix(), 2) // allow for 2 sec diff on slow CI
		assert.Greater(t, result.ValidUntil.Unix(), result.ValidFrom.Unix())

		// credential subject
		var subjects []revocation.StatusList2021CredentialSubject
		err = result.UnmarshalCredentialSubject(&subjects)
		require.NoError(t, err)
		require.Len(t, subjects, 1)
		assert.Equal(t, subjects[0].ID, issuerURL.JoinPath("statuslist", "1").String())
		assert.Equal(t, subjects[0].Type, revocation.StatusList2021CredentialSubjectType)
		assert.Equal(t, subjects[0].StatusPurpose, revocation.StatusPurposeRevocation)
		assert.NotEmpty(t, subjects[0].EncodedList, "")

		// verify credential -> trust is not added automatically
		vStoreMock := verifier.NewMockStore(ctrl)
		vStoreMock.EXPECT().GetRevocations(gomock.Any()).Return(nil, verifier.ErrNotFound)
		vDIDResolverMock := resolver.NewMockDIDResolver(ctrl)
		vDIDResolverMock.EXPECT().Resolve(gomock.Any(), gomock.Any())
		vKeyResolverMock := resolver.NewMockKeyResolver(ctrl)
		vKeyResolverMock.EXPECT().ResolveKeyByID(gomock.Any(), gomock.Any(), gomock.Any()).Return(signingKey.Public(), nil)
		verif := verifier.NewVerifier(vStoreMock, vDIDResolverMock, vKeyResolverMock, jsonldManager, trustConfig, &revocation.StatusList2021{})
		assert.NoError(t, verif.Verify(*result, true, true, nil))
	})
	t.Run("error - unknown status list credential", func(t *testing.T) {
		sut := issuer{statusListStore: NewTestStatusListStore(t, issuerDID)}

		result, err := sut.StatusList(ctx, issuerDID, 1)

		assert.ErrorIs(t, err, vcr.ErrNotFound)
		assert.Nil(t, result)
	})
	t.Run("error - issuance failed", func(t *testing.T) {
		db := storage.NewTestStorageEngine(t).GetSQLDatabase()
		storage.AddDIDtoSQLDB(t, db, issuerDID)
		status := revocation.NewStatusList2021(db, nil)
		status.Sign = func(_ context.Context, unsignedCredential vc.VerifiableCredential, _ string) (*vc.VerifiableCredential, error) {
			return &unsignedCredential, nil
		}
		_, err = status.Create(ctx, issuerDID, revocation.StatusPurposeRevocation)
		require.NoError(t, err)
		db.Exec("DROP TABLE status_list_credential")

		sut := issuer{
			jsonldManager:   jsonldManager,
			keyStore:        keyStore,
			trustConfig:     trustConfig,
			statusListStore: status,
		}

		result, err := sut.StatusList(ctx, issuerDID, 1)

		assert.Nil(t, result)
		assert.Error(t, err, "issuance failed")
	})
	t.Run("error - did:nuts", func(t *testing.T) {
		sut := issuer{statusListStore: NewTestStatusListStore(t)}
		issuerNuts := did.MustParseDID("did:nuts:123")

		result, err := sut.StatusList(ctx, issuerNuts, 1)

		assert.ErrorContains(t, err, "unsupported DID method: nuts")
		assert.Nil(t, result)
	})
}

func NewTestStatusListStore(t testing.TB, dids ...did.DID) *revocation.StatusList2021 {
	storageEngine := storage.NewTestStorageEngine(t)
	db := storageEngine.GetSQLDatabase()
	storage.AddDIDtoSQLDB(t, db, dids...)
	cs := revocation.NewStatusList2021(db, nil)
	cs.Sign = func(_ context.Context, unsignedCredential vc.VerifiableCredential, _ string) (*vc.VerifiableCredential, error) {
		unsignedCredential.ID, _ = ssi.ParseURI("test-credential")
		bs, err := json.Marshal(unsignedCredential)
		require.NoError(t, err)
		unsignedWithRawField := new(vc.VerifiableCredential)
		require.NoError(t, json.Unmarshal(bs, unsignedWithRawField))
		return unsignedWithRawField, nil
	}
	return cs
}

func Test_combinedStore_Diagnostics(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store1 := NewMockStore(ctrl)
	store1.EXPECT().Diagnostics().Return([]core.DiagnosticResult{
		core.GenericDiagnosticResult{
			Title:   "issued_credentials_count",
			Outcome: 10,
		},
		core.GenericDiagnosticResult{
			Title:   "other_diagnostic_1",
			Outcome: "foo",
		},
	})
	store2 := NewMockStore(ctrl)
	store2.EXPECT().Diagnostics().Return([]core.DiagnosticResult{
		core.GenericDiagnosticResult{
			Title:   "issued_credentials_count",
			Outcome: 15,
		},
		core.GenericDiagnosticResult{
			Title:   "other_diagnostic_2",
			Outcome: "bar",
		},
	})

	sut := combinedStore{
		didNutsStore:   store1,
		otherDIDsStore: store2,
	}

	diagnostics := sut.Diagnostics()

	// assert that it merges the diagnostics from the 2 stores
	assert.Len(t, diagnostics, 3)
	assert.Contains(t, diagnostics, core.GenericDiagnosticResult{
		Title:   "issued_credentials_count",
		Outcome: 25,
	})
	assert.Contains(t, diagnostics, core.GenericDiagnosticResult{
		Title:   "other_diagnostic_1",
		Outcome: "foo",
	})
	assert.Contains(t, diagnostics, core.GenericDiagnosticResult{
		Title:   "other_diagnostic_2",
		Outcome: "bar",
	})
}

func Test_combinedStore_GetCredential(t *testing.T) {
	t.Run("issued by did:nuts DID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		nutsStore := NewMockStore(ctrl)
		nutsStore.EXPECT().GetCredential(gomock.Any()).Return(&vc.VerifiableCredential{}, nil)
		webStore := NewMockStore(ctrl)
		sut := combinedStore{
			didNutsStore:   nutsStore,
			otherDIDsStore: webStore,
		}

		_, err := sut.GetCredential(nutsIssuerDID.URI())

		assert.NoError(t, err)
	})
	t.Run("issued by did:web", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		nutsStore := NewMockStore(ctrl)
		webStore := NewMockStore(ctrl)
		webStore.EXPECT().GetCredential(gomock.Any()).Return(&vc.VerifiableCredential{}, nil)
		sut := combinedStore{
			didNutsStore:   nutsStore,
			otherDIDsStore: webStore,
		}

		_, err := sut.GetCredential(webIssuerDID.URI())

		assert.NoError(t, err)
	})
}

func Test_combinedStore_StoreCredential(t *testing.T) {
	t.Run("issued by did:nuts DID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		nutsStore := NewMockStore(ctrl)
		nutsStore.EXPECT().StoreCredential(gomock.Any()).Return(nil)
		webStore := NewMockStore(ctrl)
		sut := combinedStore{
			didNutsStore:   nutsStore,
			otherDIDsStore: webStore,
		}

		err := sut.StoreCredential(vc.VerifiableCredential{
			Issuer: nutsIssuerDID.URI(),
		})

		assert.NoError(t, err)
	})
	t.Run("issued by did:web", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		nutsStore := NewMockStore(ctrl)
		webStore := NewMockStore(ctrl)
		webStore.EXPECT().StoreCredential(gomock.Any()).Return(nil)
		sut := combinedStore{
			didNutsStore:   nutsStore,
			otherDIDsStore: webStore,
		}

		err := sut.StoreCredential(vc.VerifiableCredential{
			Issuer: webIssuerDID.URI(),
		})

		assert.NoError(t, err)
	})
}

func Test_combinedStore_GetRevocation(t *testing.T) {
	t.Run("issued by did:nuts DID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		nutsStore := NewMockStore(ctrl)
		nutsStore.EXPECT().GetRevocation(gomock.Any()).Return(&credential.Revocation{}, nil)
		webStore := NewMockStore(ctrl)
		sut := combinedStore{
			didNutsStore:   nutsStore,
			otherDIDsStore: webStore,
		}

		_, err := sut.GetRevocation(nutsIssuerDID.URI())

		assert.NoError(t, err)
	})
	t.Run("issued by did:web", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		nutsStore := NewMockStore(ctrl)
		webStore := NewMockStore(ctrl)
		webStore.EXPECT().GetRevocation(gomock.Any()).Return(&credential.Revocation{}, nil)
		sut := combinedStore{
			didNutsStore:   nutsStore,
			otherDIDsStore: webStore,
		}

		_, err := sut.GetRevocation(webIssuerDID.URI())

		assert.NoError(t, err)
	})
}

func Test_combinedStore_StoreRevocation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	nutsStore := NewMockStore(ctrl)
	nutsStore.EXPECT().StoreRevocation(gomock.Any()).Return(nil)
	webStore := NewMockStore(ctrl)
	sut := combinedStore{
		didNutsStore:   nutsStore,
		otherDIDsStore: webStore,
	}

	err := sut.StoreRevocation(credential.Revocation{
		Issuer: nutsIssuerDID.URI(),
	})

	assert.NoError(t, err)
}

func Test_combinedStore_SearchCredential(t *testing.T) {
	t.Run("issued by did:nuts DID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		nutsStore := NewMockStore(ctrl)
		nutsStore.EXPECT().SearchCredential(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		webStore := NewMockStore(ctrl)
		sut := combinedStore{
			didNutsStore:   nutsStore,
			otherDIDsStore: webStore,
		}

		_, err := sut.SearchCredential(vc.VerifiableCredentialTypeV1URI(), issuerDID, nil)

		assert.NoError(t, err)
	})
	t.Run("issued by did:web", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		nutsStore := NewMockStore(ctrl)
		webStore := NewMockStore(ctrl)
		webStore.EXPECT().SearchCredential(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		sut := combinedStore{
			didNutsStore:   nutsStore,
			otherDIDsStore: webStore,
		}

		_, err := sut.SearchCredential(vc.VerifiableCredentialTypeV1URI(), did.MustParseDID("did:web:example.com"), nil)

		assert.NoError(t, err)
	})
}

func Test_combinedStore_Close(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	nutsStore := NewMockStore(ctrl)
	nutsStore.EXPECT().Close()
	webStore := NewMockStore(ctrl)
	sut := combinedStore{
		didNutsStore:   nutsStore,
		otherDIDsStore: webStore,
	}

	err := sut.Close()

	assert.NoError(t, err)
}
