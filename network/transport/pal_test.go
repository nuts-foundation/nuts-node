package transport

import (
	"errors"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDecryptPAL(t *testing.T) {
	keyDID, _ := did.ParseDIDURL("did:nuts:123#key1")
	testDID, _ := did.ParseDID("did:nuts:123")
	testDID2, _ := did.ParseDID("did:nuts:456")
	dummyPAL := [][]byte{{1}}

	createContext := func(t *testing.T, nodeDID did.DID) (*gomock.Controller, NodeDIDResolver, *types.MockDocResolver, *crypto.MockDecrypter) {
		ctrl := gomock.NewController(t)
		nodeDIDResolver := &FixedNodeDIDResolver{NodeDID: nodeDID}
		docResolver := types.NewMockDocResolver(ctrl)
		decrypter := crypto.NewMockDecrypter(ctrl)
		return ctrl, nodeDIDResolver, docResolver, decrypter
	}

	t.Run("errors when node DID is not set", func(t *testing.T) {
		ctrl, nodeDIDResolver, docResolver, decrypter := createContext(t, did.DID{})
		defer ctrl.Finish()

		pal, err := DecryptPAL(nodeDIDResolver, docResolver, decrypter, dummyPAL)
		assert.EqualError(t, err, "node DID is not set")
		assert.Nil(t, pal)
	})

	t.Run("errors when resolving the node DID document fails", func(t *testing.T) {
		ctrl, nodeDIDResolver, docResolver, decrypter := createContext(t, *testDID)
		defer ctrl.Finish()

		docResolver.EXPECT().Resolve(*testDID, nil).Return(nil, nil, errors.New("random error"))

		_, err := DecryptPAL(nodeDIDResolver, docResolver, decrypter, dummyPAL)

		assert.EqualError(t, err, "random error")
	})

	t.Run("returns empty result for empty PAL", func(t *testing.T) {
		ctrl, nodeDIDResolver, docResolver, decrypter := createContext(t, *testDID)
		defer ctrl.Finish()

		pal, err := DecryptPAL(nodeDIDResolver, docResolver, decrypter, dag.EncryptedPAL{})

		assert.NoError(t, err)
		assert.Empty(t, pal)
	})

	t.Run("errors when decryption fails because the key-agreement key could not be found", func(t *testing.T) {
		ctrl, nodeDIDResolver, docResolver, decrypter := createContext(t, *testDID)
		defer ctrl.Finish()

		docResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return(nil, crypto.ErrKeyNotFound)

		pal, err := DecryptPAL(nodeDIDResolver, docResolver, decrypter, dummyPAL)

		assert.EqualError(t, err, fmt.Sprintf("private key of DID keyAgreement not found (kid=%s)", keyDID.String()))
		assert.Nil(t, pal)
	})

	t.Run("valid transaction is decrypted successfully", func(t *testing.T) {
		ctrl, nodeDIDResolver, docResolver, decrypter := createContext(t, *testDID)
		defer ctrl.Finish()

		docResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return(append(append([]byte(testDID.String()), '\n'), []byte(testDID2.String())...), nil)

		pal, err := DecryptPAL(nodeDIDResolver, docResolver, decrypter, dummyPAL)

		assert.NoError(t, err)
		assert.Equal(t, dag.PAL([]did.DID{*testDID, *testDID2}), pal)
	})

}
