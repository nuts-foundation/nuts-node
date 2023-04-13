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

package transport

import (
	"context"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_AutoNodeDIDResolver(t *testing.T) {
	ctx := context.Background()
	// Local vendor
	didLocal, _ := did.ParseDID("did:nuts:local")
	key0ID := *didLocal
	key0ID.Fragment = "key-0"
	key1ID := *didLocal
	key1ID.Fragment = "key-1"

	// Other vendor
	didOther, _ := did.ParseDID("did:nuts:other")
	keyOther := *didOther
	keyOther.Fragment = "key-1"

	didDocuments := []did.Document{
		// Other
		{
			ID: *didOther,
			CapabilityInvocation: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: keyOther}},
			},
		},
		// Local
		{
			ID: *didLocal,
			CapabilityInvocation: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: key0ID}},
				{VerificationMethod: &did.VerificationMethod{ID: key1ID}},
			},
		},
	}
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		keyResolver := crypto.NewMockKeyResolver(ctrl)
		docFinder := types.NewMockDocFinder(ctrl)

		keyResolver.EXPECT().List(ctx).Return([]string{key0ID.String(), key1ID.String()})
		docFinder.EXPECT().Find(didservice.IsActive(), gomock.Any(), didservice.ByServiceType(NutsCommServiceType)).Return(didDocuments, nil)

		actual, err := AutoResolveNodeDID(ctx, keyResolver, docFinder)

		require.NoError(t, err)
		assert.Equal(t, *didLocal, actual)
	})
	t.Run("no private keys in keystore", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		keyResolver := crypto.NewMockKeyResolver(ctrl)
		docFinder := types.NewMockDocFinder(ctrl)

		keyResolver.EXPECT().List(ctx).Return([]string{})
		docFinder.EXPECT().Find(didservice.IsActive(), gomock.Any(), didservice.ByServiceType(NutsCommServiceType)).Return(didDocuments, nil)

		actual, err := AutoResolveNodeDID(ctx, keyResolver, docFinder)

		assert.NoError(t, err)
		assert.Empty(t, actual)
	})
	t.Run("no DID documents match", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		keyResolver := crypto.NewMockKeyResolver(ctrl)
		docFinder := types.NewMockDocFinder(ctrl)

		keyResolver.EXPECT().List(ctx).Return([]string{"non-matching-KID"})
		docFinder.EXPECT().Find(didservice.IsActive(), gomock.Any(), didservice.ByServiceType(NutsCommServiceType)).Return(didDocuments, nil)

		actual, err := AutoResolveNodeDID(ctx, keyResolver, docFinder)

		assert.NoError(t, err)
		assert.Empty(t, actual)
	})
}
