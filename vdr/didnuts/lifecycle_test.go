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
 */

package didnuts

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	crypto2 "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var jwkString = `{"crv":"P-256","kid":"did:nuts:3gU9z3j7j4VCboc3qq3Vc5mVVGDNGjfg32xokeX8c8Zn#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE","kty":"EC","x":"Qn6xbZtOYFoLO2qMEAczcau9uGGWwa1bT+7JmAVLtg4=","y":"d20dD0qlT+d1djVpAfrfsAfKOUxKwKkn1zqFSIuJ398="},"type":"JsonWebKey2020"}`

func TestDefaultCreationOptions(t *testing.T) {
	ops := management.EmptyCreationOptions()

	keyFlags, err := parseOptions(ops)
	assert.NoError(t, err)
	assert.True(t, keyFlags.Is(management.AssertionMethodUsage))
	assert.False(t, keyFlags.Is(management.AuthenticationUsage))
	assert.False(t, keyFlags.Is(management.CapabilityDelegationUsage))
	assert.True(t, keyFlags.Is(management.CapabilityInvocationUsage))
	assert.True(t, keyFlags.Is(management.KeyAgreementUsage))
}

func TestManager_Create2(t *testing.T) {
	defaultOptions := management.EmptyCreationOptions()

	t.Run("ok", func(t *testing.T) {
		t.Run("defaults", func(t *testing.T) {
			ctx := newManagerTestContext(t)
			var txTemplate network.Template
			ctx.mockNetwork.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tx network.Template) (hash.SHA256Hash, error) {
				txTemplate = tx
				return hash.EmptyHash(), nil
			})

			doc, key, err := ctx.manager.Create(nil, defaultOptions)
			assert.NoError(t, err, "create should not return an error")
			assert.NotNil(t, doc, "create should return a document")
			assert.NotNil(t, key, "create should return a Key")
			assert.Equal(t, did.MustParseDIDURL(ctx.mockKeyStore.key.KID()).DID, doc.ID, "the DID Doc should have the expected id")
			assert.Len(t, doc.VerificationMethod, 1, "it should have one verificationMethod")
			assert.Equal(t, ctx.mockKeyStore.key.KID(), doc.VerificationMethod[0].ID.String(),
				"verificationMethod should have the correct id")
			assert.Len(t, doc.CapabilityInvocation, 1, "it should have 1 CapabilityInvocation")
			assert.Equal(t, doc.CapabilityInvocation[0].VerificationMethod, doc.VerificationMethod[0], "the assertionMethod should be a pointer to the verificationMethod")
			assert.Len(t, doc.AssertionMethod, 1, "it should have 1 AssertionMethod")
			assert.Equal(t, DIDDocumentType, txTemplate.Type)
			payload, _ := json.Marshal(doc)
			assert.Equal(t, payload, txTemplate.Payload)
			assert.Equal(t, key, txTemplate.Key)
			assert.Empty(t, txTemplate.AdditionalPrevs)
		})

		t.Run("unknown option", func(t *testing.T) {
			_, _, err := (&Manager{}).Create(nil, management.EmptyCreationOptions().With(""))
			assert.EqualError(t, err, "unknown option: string")
		})

		t.Run("all keys", func(t *testing.T) {
			ctx := newManagerTestContext(t)
			ctx.mockNetwork.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).Return(nil, nil)

			keyFlags := management.AssertionMethodUsage |
				management.AuthenticationUsage |
				management.CapabilityDelegationUsage |
				management.CapabilityInvocationUsage |
				management.KeyAgreementUsage
			ops := management.EmptyCreationOptions().With(KeyFlag(keyFlags))
			doc, _, err := ctx.manager.Create(nil, ops)

			require.NoError(t, err)

			assert.Len(t, doc.AssertionMethod, 1)
			assert.Len(t, doc.Authentication, 1)
			assert.Len(t, doc.CapabilityDelegation, 1)
			assert.Len(t, doc.CapabilityInvocation, 1)
			assert.Len(t, doc.KeyAgreement, 1)
		})
	})

	t.Run("error - failed to create key", func(t *testing.T) {
		ctx := newManagerTestContext(t)
		mock := crypto2.NewMockKeyStore(ctx.ctrl)
		ctx.manager.KeyStore = mock
		mock.EXPECT().New(gomock.Any(), gomock.Any()).Return(nil, errors.New("b00m!"))

		_, _, err := ctx.manager.Create(nil, management.EmptyCreationOptions())

		assert.EqualError(t, err, "b00m!")
	})
}

func TestManager_Deactivate(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDIDURL("did:nuts:123#key-1")
	ctx := newManagerTestContext(t)
	currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
	currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
	ctx.mockResolver.EXPECT().Resolve(*id, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &resolver.DocumentMetadata{}, nil)
	ctx.mockDIDStore.EXPECT().Resolve(*id, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &resolver.DocumentMetadata{}, nil)
	ctx.mockResolver.EXPECT().Resolve(*id, nil).Return(&currentDIDDocument, &resolver.DocumentMetadata{}, nil)
	expectedDocument := CreateDocument()
	expectedDocument.ID = *id
	ctx.mockNetwork.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).Do(func(_ context.Context, template network.Template) (dag.Transaction, error) {
		var didDocument did.Document
		_ = json.Unmarshal(template.Payload, &didDocument)
		assert.Len(t, didDocument.VerificationMethod, 0)
		assert.Len(t, didDocument.Controller, 0)
		return nil, nil
	})

	err := ctx.manager.Deactivate(ctx.audit, *id)

	require.NoError(t, err)
}

func Test_didKIDNamingFunc(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		keyID, err := didKIDNamingFunc(privateKey.PublicKey)
		require.NoError(t, err)
		assert.NotEmpty(t, keyID)
		assert.Contains(t, keyID, "did:nuts")
	})

	t.Run("ok - predefined key", func(t *testing.T) {
		pub, err := jwkToPublicKey(t, jwkString)
		require.NoError(t, err)

		keyID, err := didKIDNamingFunc(pub)
		require.NoError(t, err)
		assert.Equal(t, keyID, "did:nuts:3gU9z3j7j4VCboc3qq3Vc5mVVGDNGjfg32xokeX8c8Zn#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE", keyID)
	})

	t.Run("nok - wrong key type", func(t *testing.T) {
		keyID, err := didKIDNamingFunc(unknownPublicKey{})
		assert.EqualError(t, err, "could not generate kid: invalid key type 'didnuts.unknownPublicKey' for jwk.New")
		assert.Empty(t, keyID)
	})
}

func Test_didSubKIDNamingFunc(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		owningDID, _ := did.ParseDID("did:nuts:bladiebla")

		keyID, err := didSubKIDNamingFunc(*owningDID)(privateKey.PublicKey)
		require.NoError(t, err)
		parsedKeyID, err := did.ParseDIDURL(keyID)
		require.NoError(t, err)
		// Make sure the idString part of the key ID is taken from the owning DID document
		assert.Equal(t, parsedKeyID.ID, owningDID.ID)
		assert.NotEmpty(t, parsedKeyID.Fragment)
	})
}

type unknownPublicKey struct{}

func jwkToPublicKey(t *testing.T, jwkStr string) (crypto.PublicKey, error) {
	t.Helper()
	keySet, err := jwk.ParseString(jwkStr)
	require.NoError(t, err)
	key, _ := keySet.Key(0)
	var rawKey crypto.PublicKey
	if err = key.Raw(&rawKey); err != nil {
		return nil, err
	}
	return rawKey, nil
}
