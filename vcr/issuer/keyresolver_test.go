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
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
)

func Test_vdrKeyResolver_ResolveAssertionKey(t *testing.T) {
	ctx := context.Background()
	issuerDID, _ := did.ParseDID("did:nuts:123")
	methodID := did.DIDURL{DID: *issuerDID}
	methodID.Fragment = "abc"
	publicKey := crypto.NewTestKey(issuerDID.String() + "abc").Public()
	newMethod, err := did.NewVerificationMethod(methodID, ssi.JsonWebKey2020, *issuerDID, publicKey)
	require.NoError(t, err)
	docWithAssertionKey := &did.Document{}
	docWithAssertionKey.AddAssertionMethod(newMethod)

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockPubKeyResolver := resolver.NewMockKeyResolver(ctrl)
		mockPubKeyResolver.EXPECT().ResolveKey(*issuerDID, nil, resolver.NutsSigningKeyType).Return(methodID.URI(), publicKey, nil)
		mockPrivKeyResolver := crypto.NewMockKeyResolver(ctrl)
		mockPrivKeyResolver.EXPECT().Resolve(ctx, methodID.String()).Return(crypto.NewTestKey(methodID.String()), nil)

		sut := vdrKeyResolver{
			publicKeyResolver:  mockPubKeyResolver,
			privateKeyResolver: mockPrivKeyResolver,
		}

		key, err := sut.ResolveAssertionKey(ctx, *issuerDID)

		assert.NotNil(t, key)
		assert.Implements(t, (*crypto.Key)(nil), key)
		assert.NoError(t, err)
	})

	t.Run("document for issuer not found in vdr", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockPubKeyResolver := resolver.NewMockKeyResolver(ctrl)
		mockPubKeyResolver.EXPECT().ResolveKey(*issuerDID, nil, resolver.NutsSigningKeyType).Return(ssi.URI{}, nil, errors.New("not found"))
		mockPrivKeyResolver := crypto.NewMockKeyResolver(ctrl)

		sut := vdrKeyResolver{
			publicKeyResolver:  mockPubKeyResolver,
			privateKeyResolver: mockPrivKeyResolver,
		}

		key, err := sut.ResolveAssertionKey(ctx, *issuerDID)

		assert.Nil(t, key)
		assert.EqualError(t, err, "invalid issuer: not found")
	})

	t.Run("key not found in crypto", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockPubKeyResolver := resolver.NewMockKeyResolver(ctrl)
		mockPubKeyResolver.EXPECT().ResolveKey(*issuerDID, nil, resolver.NutsSigningKeyType).Return(methodID.URI(), publicKey, nil)
		mockPrivKeyResolver := crypto.NewMockKeyResolver(ctrl)
		mockPrivKeyResolver.EXPECT().Resolve(ctx, methodID.String()).Return(nil, errors.New("not found"))

		sut := vdrKeyResolver{
			publicKeyResolver:  mockPubKeyResolver,
			privateKeyResolver: mockPrivKeyResolver,
		}

		key, err := sut.ResolveAssertionKey(ctx, *issuerDID)
		assert.Nil(t, key)
		assert.EqualError(t, err, "failed to resolve assertionKey: could not resolve key from keyStore: not found")
	})
}
