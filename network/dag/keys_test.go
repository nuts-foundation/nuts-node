/*
 * Copyright (C) 2023 Nuts community
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

package dag

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
)

func TestNutsKeyResolver_ResolvePublicKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	didResolver := resolver.NewMockDIDResolver(ctrl)
	keyResolver := SourceTXKeyResolver{Resolver: didResolver}
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	doc := &did.Document{
		ID: did.MustParseDID("did:nuts:123"),
	}
	mockKID := did.DIDURL{DID: doc.ID}
	mockKID.Fragment = "key-1"
	vm, err := did.NewVerificationMethod(mockKID, ssi.JsonWebKey2020, doc.ID, pk.Public())
	require.NoError(t, err)
	doc.AddAssertionMethod(vm)

	t.Run("ok by hash", func(t *testing.T) {
		didResolver.EXPECT().Resolve(doc.ID, gomock.Any()).Do(func(arg0 interface{}, arg1 interface{}) {
			resolveMetadata := arg1.(*resolver.ResolveMetadata)
			assert.Equal(t, hash.EmptyHash(), *resolveMetadata.SourceTransaction)
		}).Return(doc, nil, nil)

		key, err := keyResolver.ResolvePublicKey(mockKID.String(), []hash.SHA256Hash{hash.EmptyHash()})
		require.NoError(t, err)

		assert.NotNil(t, key)
	})

}
