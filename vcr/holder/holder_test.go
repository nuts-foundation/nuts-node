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

package holder

import (
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

var testDID = vdr.TestDIDA

func TestHolder_BuildVP(t *testing.T) {
	var kid = vdr.TestMethodDIDA.String()
	testCredentialJSON := `
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://nuts.nl/credentials/v1",
        "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
    ],
    "credentialSubject": {
        "company": {
            "city": "Hengelo",
            "name": "De beste zorg"
        },
        "id": "` + testDID.String() + `"
    },
    "id": "did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H#d2aa8189-db59-4dad-a3e5-60ca54f8fcc0",
    "issuanceDate": "2021-12-24T13:21:29.087205+01:00",
    "issuer": "did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H",
    "proof": {
        "created": "2021-12-24T13:21:29.087205+01:00",
        "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..hPM2GLc1K9d2D8Sbve004x9SumjLqaXTjWhUhvqWRwxfRWlwfp5gHDUYuRoEjhCXfLt-_u-knChVmK980N3LBw",
        "proofPurpose": "assertionMethod",
        "type": "JsonWebSignature2020",
        "verificationMethod": "` + kid + `"
    },
    "type": [
        "CompanyCredential",
        "VerifiableCredential"
    ]
}`
	testCredential := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(testCredentialJSON), &testCredential)
	key := vdr.TestMethodDIDAPrivateKey()
	jsonldManager := jsonld.NewTestJSONLDManager(t)
	testDID := vdr.TestDIDA
	ctx := audit.TestContext()

	keyStorage := crypto.NewMemoryStorage()
	_ = keyStorage.SavePrivateKey(ctx, key.KID(), key.PrivateKey)
	keyStore := crypto.NewTestCryptoInstance(keyStorage)

	options := PresentationOptions{ProofOptions: proof.ProofOptions{}}

	t.Run("ok - one VC", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		keyResolver := types.NewMockKeyResolver(ctrl)

		keyResolver.EXPECT().ResolveAssertionKeyID(testDID).Return(ssi.MustParseURI(kid), nil)

		holder := New(keyResolver, keyStore, nil, jsonldManager)

		resultingPresentation, err := holder.BuildVP(ctx, []vc.VerifiableCredential{testCredential}, options, &testDID, false)

		require.NoError(t, err)
		assert.NotNil(t, resultingPresentation)
	})
	t.Run("ok - custom options", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		specialType := ssi.MustParseURI("SpecialPresentation")
		options := PresentationOptions{
			AdditionalContexts: []ssi.URI{credential.NutsV1ContextURI},
			AdditionalTypes:    []ssi.URI{specialType},
			ProofOptions: proof.ProofOptions{
				ProofPurpose: "authentication",
			},
		}
		keyResolver := types.NewMockKeyResolver(ctrl)

		keyResolver.EXPECT().ResolveAssertionKeyID(testDID).Return(ssi.MustParseURI(kid), nil)

		holder := New(keyResolver, keyStore, nil, jsonldManager)

		resultingPresentation, err := holder.BuildVP(ctx, []vc.VerifiableCredential{testCredential}, options, &testDID, false)

		require.NoError(t, err)
		require.NotNil(t, resultingPresentation)
		assert.True(t, resultingPresentation.IsType(specialType))
		assert.True(t, resultingPresentation.ContainsContext(credential.NutsV1ContextURI))
		proofs, _ := resultingPresentation.Proofs()
		require.Len(t, proofs, 1)
		assert.Equal(t, proofs[0].ProofPurpose, "authentication")
	})
	t.Run("ok - multiple VCs", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		keyResolver := types.NewMockKeyResolver(ctrl)

		keyResolver.EXPECT().ResolveAssertionKeyID(testDID).Return(vdr.TestMethodDIDA.URI(), nil)

		holder := New(keyResolver, keyStore, nil, jsonldManager)

		resultingPresentation, err := holder.BuildVP(ctx, []vc.VerifiableCredential{testCredential, testCredential}, options, &testDID, false)

		assert.NoError(t, err)
		assert.NotNil(t, resultingPresentation)
	})
	t.Run("validation", func(t *testing.T) {
		created := time.Now()
		options := PresentationOptions{ProofOptions: proof.ProofOptions{Created: created}}

		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := types.NewMockKeyResolver(ctrl)
			mockVerifier := verifier.NewMockVerifier(ctrl)
			mockVerifier.EXPECT().Validate(testCredential, &created)

			keyResolver.EXPECT().ResolveAssertionKeyID(testDID).Return(ssi.MustParseURI(kid), nil)

			holder := New(keyResolver, keyStore, mockVerifier, jsonldManager)

			resultingPresentation, err := holder.BuildVP(ctx, []vc.VerifiableCredential{testCredential}, options, &testDID, true)

			assert.NoError(t, err)
			assert.NotNil(t, resultingPresentation)
		})
		t.Run("error", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := types.NewMockKeyResolver(ctrl)
			mockVerifier := verifier.NewMockVerifier(ctrl)
			mockVerifier.EXPECT().Validate(testCredential, &created).Return(errors.New("failed"))

			keyResolver.EXPECT().ResolveAssertionKeyID(testDID).Return(ssi.MustParseURI(kid), nil)

			holder := New(keyResolver, keyStore, mockVerifier, jsonldManager)

			resultingPresentation, err := holder.BuildVP(ctx, []vc.VerifiableCredential{testCredential}, options, &testDID, true)

			assert.EqualError(t, err, "invalid credential (id=did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H#d2aa8189-db59-4dad-a3e5-60ca54f8fcc0): failed")
			assert.Nil(t, resultingPresentation)
		})
	})
	t.Run("deriving signer from VCs", func(t *testing.T) {
		options := PresentationOptions{ProofOptions: proof.ProofOptions{}}

		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)

			keyResolver := types.NewMockKeyResolver(ctrl)

			keyResolver.EXPECT().ResolveAssertionKeyID(testDID).Return(ssi.MustParseURI(kid), nil)

			holder := New(keyResolver, keyStore, nil, jsonldManager)

			resultingPresentation, err := holder.BuildVP(ctx, []vc.VerifiableCredential{testCredential, testCredential}, options, nil, false)

			assert.NoError(t, err)
			assert.NotNil(t, resultingPresentation)
		})
		t.Run("error - not all VCs have the same id", func(t *testing.T) {
			secondCredential := testCredential
			secondCredential.CredentialSubject = []interface{}{map[string]interface{}{"id": vdr.TestDIDB.String()}}

			ctrl := gomock.NewController(t)

			keyResolver := types.NewMockKeyResolver(ctrl)

			holder := New(keyResolver, keyStore, nil, jsonldManager)

			resultingPresentation, err := holder.BuildVP(ctx, []vc.VerifiableCredential{testCredential, secondCredential}, options, nil, false)

			assert.EqualError(t, err, "unable to resolve signer DID from VCs for creating VP: not all VCs have the same credentialSubject.id")
			assert.Nil(t, resultingPresentation)
		})
		t.Run("error -  not all VCs have an id", func(t *testing.T) {
			secondCredential := testCredential
			secondCredential.CredentialSubject = []interface{}{}

			ctrl := gomock.NewController(t)

			keyResolver := types.NewMockKeyResolver(ctrl)

			holder := New(keyResolver, keyStore, nil, jsonldManager)

			resultingPresentation, err := holder.BuildVP(ctx, []vc.VerifiableCredential{testCredential, secondCredential}, options, nil, false)

			assert.EqualError(t, err, "unable to resolve signer DID from VCs for creating VP: not all VCs contain credentialSubject.id")
			assert.Nil(t, resultingPresentation)
		})
	})
}
