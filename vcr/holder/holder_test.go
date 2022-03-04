package holder

import (
	"encoding/json"
	"errors"
	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

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
        "id": "` + vdr.TestDIDA.String() + `"
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
	key := crypto.NewTestKey(kid)

	t.Run("ok - one VC", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		keyResolver := types.NewMockKeyResolver(ctrl)
		keyStore := crypto.NewMockKeyStore(ctrl)

		keyResolver.EXPECT().ResolveAssertionKeyID(*vdr.TestDIDA).Return(ssi.MustParseURI(kid), nil)
		keyStore.EXPECT().Resolve(vdr.TestMethodDIDA.URI().String()).Return(key, nil)

		contextLoader, _ := signature.NewContextLoader(false)
		holder := New(keyResolver, keyStore, nil, contextLoader)

		options := proof.ProofOptions{}
		resultingPresentation, err := holder.BuildVP([]vc.VerifiableCredential{testCredential}, options, vdr.TestDIDA, false)

		assert.NoError(t, err)
		assert.NotNil(t, resultingPresentation)
	})
	t.Run("ok - multiple VCs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		keyResolver := types.NewMockKeyResolver(ctrl)
		keyStore := crypto.NewMockKeyStore(ctrl)

		keyResolver.EXPECT().ResolveAssertionKeyID(*vdr.TestDIDA).Return(vdr.TestMethodDIDA.URI(), nil)
		keyStore.EXPECT().Resolve(vdr.TestMethodDIDA.URI().String()).Return(key, nil)

		contextLoader, _ := signature.NewContextLoader(false)
		holder := New(keyResolver, keyStore, nil, contextLoader)

		options := proof.ProofOptions{}
		resultingPresentation, err := holder.BuildVP([]vc.VerifiableCredential{testCredential, testCredential}, options, vdr.TestDIDA, false)

		assert.NoError(t, err)
		assert.NotNil(t, resultingPresentation)
	})
	t.Run("validation", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			created := time.Now()

			keyResolver := types.NewMockKeyResolver(ctrl)
			keyStore := crypto.NewMockKeyStore(ctrl)
			mockVerifier := verifier.NewMockVerifier(ctrl)
			mockVerifier.EXPECT().Validate(testCredential, &created)

			keyResolver.EXPECT().ResolveAssertionKeyID(*vdr.TestDIDA).Return(ssi.MustParseURI(kid), nil)
			keyStore.EXPECT().Resolve(vdr.TestMethodDIDA.URI().String()).Return(key, nil)

			contextLoader, _ := signature.NewContextLoader(false)
			holder := New(keyResolver, keyStore, mockVerifier, contextLoader)

			options := proof.ProofOptions{Created: created}
			resultingPresentation, err := holder.BuildVP([]vc.VerifiableCredential{testCredential}, options, vdr.TestDIDA, true)

			assert.NoError(t, err)
			assert.NotNil(t, resultingPresentation)
		})
		t.Run("error", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			created := time.Now()

			keyResolver := types.NewMockKeyResolver(ctrl)
			keyStore := crypto.NewMockKeyStore(ctrl)
			mockVerifier := verifier.NewMockVerifier(ctrl)
			mockVerifier.EXPECT().Validate(testCredential, &created).Return(errors.New("failed"))

			keyResolver.EXPECT().ResolveAssertionKeyID(*vdr.TestDIDA).Return(ssi.MustParseURI(kid), nil)
			keyStore.EXPECT().Resolve(vdr.TestMethodDIDA.URI().String()).Return(key, nil)

			contextLoader, _ := signature.NewContextLoader(false)
			holder := New(keyResolver, keyStore, mockVerifier, contextLoader)

			options := proof.ProofOptions{Created: created}
			resultingPresentation, err := holder.BuildVP([]vc.VerifiableCredential{testCredential}, options, vdr.TestDIDA, true)

			assert.EqualError(t, err, "invalid credential (id=did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H#d2aa8189-db59-4dad-a3e5-60ca54f8fcc0): failed")
			assert.Nil(t, resultingPresentation)
		})
	})
	t.Run("deriving signer from VCs", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			keyResolver := types.NewMockKeyResolver(ctrl)
			keyStore := crypto.NewMockKeyStore(ctrl)

			keyResolver.EXPECT().ResolveAssertionKeyID(*vdr.TestDIDA).Return(ssi.MustParseURI(kid), nil)
			keyStore.EXPECT().Resolve(vdr.TestMethodDIDA.URI().String()).Return(key, nil)

			contextLoader, _ := signature.NewContextLoader(false)
			holder := New(keyResolver, keyStore, nil, contextLoader)

			options := proof.ProofOptions{}
			resultingPresentation, err := holder.BuildVP([]vc.VerifiableCredential{testCredential, testCredential}, options, nil, false)

			assert.NoError(t, err)
			assert.NotNil(t, resultingPresentation)
		})
		t.Run("error - not all VCs have the same id", func(t *testing.T) {
			secondCredential := testCredential
			secondCredential.CredentialSubject = []interface{}{map[string]interface{}{"id": vdr.TestDIDB.String()}}

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			keyResolver := types.NewMockKeyResolver(ctrl)
			keyStore := crypto.NewMockKeyStore(ctrl)

			contextLoader, _ := signature.NewContextLoader(false)
			holder := New(keyResolver, keyStore, nil, contextLoader)

			options := proof.ProofOptions{}
			resultingPresentation, err := holder.BuildVP([]vc.VerifiableCredential{testCredential, secondCredential}, options, nil, false)

			assert.EqualError(t, err, "unable to resolve signer DID from VCs for creating VP: not all VCs have the same credentialSubject.id")
			assert.Nil(t, resultingPresentation)
		})
		t.Run("error -  not all VCs have an id", func(t *testing.T) {
			secondCredential := testCredential
			secondCredential.CredentialSubject = []interface{}{}

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			keyResolver := types.NewMockKeyResolver(ctrl)
			keyStore := crypto.NewMockKeyStore(ctrl)

			contextLoader, _ := signature.NewContextLoader(false)
			holder := New(keyResolver, keyStore, nil, contextLoader)

			options := proof.ProofOptions{}
			resultingPresentation, err := holder.BuildVP([]vc.VerifiableCredential{testCredential, secondCredential}, options, nil, false)

			assert.EqualError(t, err, "unable to resolve signer DID from VCs for creating VP: not all VCs contain credentialSubject.id")
			assert.Nil(t, resultingPresentation)
		})
	})
}
