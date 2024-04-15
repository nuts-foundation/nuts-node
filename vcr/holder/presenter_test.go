/*
 * Copyright (C) 2024 Nuts community
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

package holder

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
	"time"
)

func TestPresenter_buildPresentation(t *testing.T) {
	var kid = vdr.TestMethodDIDA.String()
	testCredential := createCredential(kid)
	key := vdr.TestMethodDIDAPrivateKey()
	jsonldManager := jsonld.NewTestJSONLDManager(t)
	testDID := vdr.TestDIDA
	ctx := audit.TestContext()

	keyStorage := crypto.NewMemoryStorage()
	_ = keyStorage.SavePrivateKey(ctx, key.KID(), key.PrivateKey)
	keyStore := crypto.NewTestCryptoInstance(keyStorage)

	t.Run("JSON-LD", func(t *testing.T) {
		t.Run("is default", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)
			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := presenter{documentLoader: jsonldManager.DocumentLoader(), keyStore: keyStore, keyResolver: keyResolver}

			result, err := w.buildPresentation(ctx, &testDID, []vc.VerifiableCredential{testCredential}, PresentationOptions{})

			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, JSONLDPresentationFormat, result.Format())
		})
		t.Run("ok - one VC", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)
			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := presenter{documentLoader: jsonldManager.DocumentLoader(), keyStore: keyStore, keyResolver: keyResolver}

			result, err := w.buildPresentation(ctx, &testDID, []vc.VerifiableCredential{testCredential}, PresentationOptions{Format: JSONLDPresentationFormat})

			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotNil(t, result.ID, "id must be set")
			assert.Equal(t, testDID, did.MustParseDIDURL(result.ID.String()).DID, "id must be the DID of the holder")
			assert.NotEmpty(t, result.ID.Fragment, "id must have a fragment")
			assert.Equal(t, JSONLDPresentationFormat, result.Format())
			ldProof, err := credential.ParseLDProof(*result)
			require.NoError(t, err)
			assert.Empty(t, ldProof.Nonce)
		})
		t.Run("ok - custom options", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			specialType := ssi.MustParseURI("SpecialPresentation")
			domain := "https://example.com"
			nonce := "the-nonce"
			options := PresentationOptions{
				AdditionalContexts: []ssi.URI{credential.NutsV1ContextURI},
				AdditionalTypes:    []ssi.URI{specialType},
				ProofOptions: proof.ProofOptions{
					ProofPurpose: "authentication",
					Domain:       &domain,
					Nonce:        &nonce,
				},
				Format: JSONLDPresentationFormat,
			}
			keyResolver := resolver.NewMockKeyResolver(ctrl)

			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := presenter{documentLoader: jsonldManager.DocumentLoader(), keyStore: keyStore, keyResolver: keyResolver}

			result, err := w.buildPresentation(ctx, &testDID, []vc.VerifiableCredential{testCredential}, options)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.True(t, result.IsType(specialType))
			assert.True(t, result.ContainsContext(credential.NutsV1ContextURI))
			var proofs []proof.LDProof
			require.NoError(t, result.UnmarshalProofValue(&proofs))
			require.Len(t, proofs, 1)
			assert.Equal(t, "authentication", proofs[0].ProofPurpose)
			assert.Equal(t, "https://example.com", *proofs[0].Domain)
			assert.Equal(t, nonce, *proofs[0].Nonce)
			assert.Equal(t, JSONLDPresentationFormat, result.Format())
		})
		t.Run("ok - multiple VCs", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)

			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(vdr.TestMethodDIDA.URI(), key.Public(), nil)

			w := presenter{documentLoader: jsonldManager.DocumentLoader(), keyStore: keyStore, keyResolver: keyResolver}

			resultingPresentation, err := w.buildPresentation(ctx, &testDID, []vc.VerifiableCredential{testCredential, testCredential}, PresentationOptions{Format: JSONLDPresentationFormat})

			assert.NoError(t, err)
			assert.NotNil(t, resultingPresentation)
		})
	})
	t.Run("JWT", func(t *testing.T) {
		options := PresentationOptions{Format: JWTPresentationFormat}
		t.Run("ok - one VC", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)
			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := presenter{documentLoader: jsonldManager.DocumentLoader(), keyStore: keyStore, keyResolver: keyResolver}

			result, err := w.buildPresentation(ctx, &testDID, []vc.VerifiableCredential{testCredential}, options)

			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotNil(t, result.ID, "id must be set")
			assert.Equal(t, testDID, did.MustParseDIDURL(result.ID.String()).DID, "id must be the DID of the holder")
			assert.NotEmpty(t, result.ID.Fragment, "id must have a fragment")
			assert.Equal(t, JWTPresentationFormat, result.Format())
			assert.NotNil(t, result.JWT())
			nonce, _ := result.JWT().Get("nonce")
			assert.Empty(t, nonce)
		})
		t.Run("ok - multiple VCs", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)

			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(vdr.TestMethodDIDA.URI(), key.Public(), nil)

			w := presenter{documentLoader: jsonldManager.DocumentLoader(), keyStore: keyStore, keyResolver: keyResolver}

			result, err := w.buildPresentation(ctx, &testDID, []vc.VerifiableCredential{testCredential, testCredential}, options)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, JWTPresentationFormat, result.Format())
			assert.NotNil(t, result.JWT())
		})
		t.Run("optional proof options", func(t *testing.T) {
			exp := time.Now().Local().Truncate(time.Second)
			domain := "https://example.com"
			nonce := "the-nonce"
			options := PresentationOptions{
				Format: JWTPresentationFormat,
				ProofOptions: proof.ProofOptions{
					Expires: &exp,
					Created: exp.Add(-1 * time.Hour),
					Domain:  &domain,
					Nonce:   &nonce,
					AdditionalProperties: map[string]interface{}{
						"custom": "claim",
					},
				},
			}

			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)
			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := presenter{documentLoader: jsonldManager.DocumentLoader(), keyStore: keyStore, keyResolver: keyResolver}

			result, err := w.buildPresentation(ctx, &testDID, []vc.VerifiableCredential{testCredential}, options)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, JWTPresentationFormat, result.Format())
			assert.NotNil(t, result.JWT())
			assert.Equal(t, *options.ProofOptions.Expires, result.JWT().Expiration().Local())
			assert.Equal(t, options.ProofOptions.Created, result.JWT().NotBefore().Local())
			assert.Equal(t, []string{domain}, result.JWT().Audience())
			actualNonce, _ := result.JWT().Get("nonce")
			assert.Equal(t, nonce, actualNonce)
			actualCustomClaim, _ := result.JWT().Get("custom")
			assert.Equal(t, "claim", actualCustomClaim)
		})
	})
	t.Run("deriving signer from VCs", func(t *testing.T) {
		options := PresentationOptions{ProofOptions: proof.ProofOptions{}}

		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)

			keyResolver.EXPECT().ResolveKey(testDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(kid), key.Public(), nil)

			w := presenter{documentLoader: jsonldManager.DocumentLoader(), keyStore: keyStore, keyResolver: keyResolver}

			resultingPresentation, err := w.buildPresentation(ctx, nil, []vc.VerifiableCredential{testCredential, testCredential}, options)

			assert.NoError(t, err)
			assert.NotNil(t, resultingPresentation)
		})
		t.Run("error - not all VCs have the same id", func(t *testing.T) {
			secondCredential := testCredential
			secondCredential.CredentialSubject = []interface{}{map[string]interface{}{"id": vdr.TestDIDB.String()}}

			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)

			w := presenter{documentLoader: jsonldManager.DocumentLoader(), keyStore: keyStore, keyResolver: keyResolver}

			resultingPresentation, err := w.buildPresentation(ctx, nil, []vc.VerifiableCredential{testCredential, secondCredential}, options)

			assert.EqualError(t, err, "unable to resolve signer DID from VCs for creating VP: not all VCs have the same credentialSubject.id")
			assert.Nil(t, resultingPresentation)
		})
		t.Run("error -  not all VCs have an id", func(t *testing.T) {
			secondCredential := testCredential
			secondCredential.CredentialSubject = []interface{}{}

			ctrl := gomock.NewController(t)

			keyResolver := resolver.NewMockKeyResolver(ctrl)

			w := presenter{documentLoader: jsonldManager.DocumentLoader(), keyStore: keyStore, keyResolver: keyResolver}

			resultingPresentation, err := w.buildPresentation(ctx, nil, []vc.VerifiableCredential{testCredential, secondCredential}, options)

			assert.EqualError(t, err, "unable to resolve signer DID from VCs for creating VP: unable to get subject DID from VC: there must be at least 1 credentialSubject")
			assert.Nil(t, resultingPresentation)
		})
	})
}

func TestPresenter_buildSubmission(t *testing.T) {
	credentials := []vc.VerifiableCredential{test.ValidNutsOrganizationCredential(t)}
	// walletDID matches the subject of the ValidNutsOrganizationCredential
	walletDID := did.MustParseDID("did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey")
	verifierDID := did.MustParseDID("did:web:example.com:iam:verifier")
	presentationDefinition := pe.PresentationDefinition{InputDescriptors: []*pe.InputDescriptor{{Constraints: &pe.Constraints{Fields: []pe.Field{{Path: []string{"$.type"}}}}}}}
	vpFormats := oauth.DefaultOpenIDSupportedFormats()

	key := vdr.TestMethodDIDAPrivateKey()
	jsonldManager := jsonld.NewTestJSONLDManager(t)
	ctx := audit.TestContext()

	keyStorage := crypto.NewMemoryStorage()
	_ = keyStorage.SavePrivateKey(ctx, key.KID(), key.PrivateKey)
	keyStore := crypto.NewTestCryptoInstance(keyStorage)
	storageEngine := storage.NewTestStorageEngine(t)

	t.Run("ok", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		keyResolver := resolver.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKey(walletDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(key.KID()), key.Public(), nil)

		w := presenter{documentLoader: jsonldManager.DocumentLoader(), keyStore: keyStore, keyResolver: keyResolver}

		vp, submission, err := w.buildSubmission(ctx, walletDID, credentials, presentationDefinition, vpFormats, BuildParams{Audience: verifierDID.String(), Expires: time.Now().Add(time.Second), Nonce: ""})

		assert.NoError(t, err)
		require.NotNil(t, vp)
		require.NotNil(t, submission)

	})
	t.Run("error - no matching credentials", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())

		w := NewSQLWallet(nil, keyStore, nil, jsonldManager, storageEngine)

		vp, submission, err := w.BuildSubmission(ctx, walletDID, presentationDefinition, vpFormats, BuildParams{Audience: verifierDID.String(), Expires: time.Now().Add(time.Second), Nonce: ""})

		assert.Equal(t, ErrNoCredentials, err)
		assert.Nil(t, vp)
		assert.Nil(t, submission)
	})
	t.Run("ok - empty presentation", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		keyResolver := resolver.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKey(walletDID, nil, resolver.NutsSigningKeyType).Return(ssi.MustParseURI(key.KID()), key.Public(), nil)
		w := presenter{documentLoader: jsonldManager.DocumentLoader(), keyStore: keyStore, keyResolver: keyResolver}

		vp, submission, err := w.buildSubmission(ctx, walletDID, credentials, pe.PresentationDefinition{}, vpFormats, BuildParams{Audience: verifierDID.String(), Expires: time.Now().Add(time.Second), Nonce: ""})

		assert.Nil(t, err)
		assert.NotNil(t, vp)
		assert.NotNil(t, submission)
	})
}
