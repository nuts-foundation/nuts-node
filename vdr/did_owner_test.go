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
 *
 */

package vdr

import (
	"context"
	"errors"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
)

func Test_cachingDocumentOwner_IsOwner(t *testing.T) {
	id := did.MustParseDID("did:nuts:example.com")
	t.Run("owned, cached", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(id, gomock.Any()).Return(nil, nil, nil)
		underlying := types.NewMockDocumentOwner(ctrl)
		underlying.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)

		documentOwner := newCachingDocumentOwner(underlying, resolver)

		result, err := documentOwner.IsOwner(context.Background(), id)
		assert.NoError(t, err)
		assert.True(t, result)
		result, err = documentOwner.IsOwner(context.Background(), id)
		assert.True(t, result)
		assert.NoError(t, err)
	})
	t.Run("not owned, cached", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(id, gomock.Any()).Return(nil, nil, nil)
		underlying := types.NewMockDocumentOwner(ctrl)
		underlying.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)

		documentOwner := newCachingDocumentOwner(underlying, resolver)

		result, err := documentOwner.IsOwner(context.Background(), id)
		assert.False(t, result)
		assert.NoError(t, err)
		result, err = documentOwner.IsOwner(context.Background(), id)
		assert.False(t, result)
		assert.NoError(t, err)
	})
	t.Run("DID does not exist", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		underlying := types.NewMockDocumentOwner(ctrl)
		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(id, gomock.Any()).Return(nil, nil, types.ErrNotFound)

		documentOwner := newCachingDocumentOwner(underlying, resolver)

		result, err := documentOwner.IsOwner(context.Background(), id)

		require.NoError(t, err)
		assert.False(t, result)
	})

	t.Run("DID is deactivated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		underlying := types.NewMockDocumentOwner(ctrl)
		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(id, gomock.Any()).Return(nil, nil, types.ErrDeactivated)

		documentOwner := newCachingDocumentOwner(underlying, resolver)

		result, err := documentOwner.IsOwner(context.Background(), id)

		require.NoError(t, err)
		assert.False(t, result)
	})
	t.Run("error - DID resolve fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		underlying := types.NewMockDocumentOwner(ctrl)
		resolver := types.NewMockDocResolver(ctrl)
		resolver.EXPECT().Resolve(id, gomock.Any()).Return(nil, nil, errors.New("b00m"))

		documentOwner := newCachingDocumentOwner(underlying, resolver)

		result, err := documentOwner.IsOwner(context.Background(), id)

		require.Error(t, err)
		assert.False(t, result)
	})
}

func Test_privateKeyDocumentOwner_IsOwner(t *testing.T) {
	keyList := []string{
		"did:nuts:example.com#key-1",
		"did:nuts:example.com",
		"",
		"not a DID",
		"did:nuts:another-did.com#key-2",
		"did:nuts:example.com#key-2",
	}
	t.Run("owned", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		keyResolver := crypto.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().List(gomock.Any()).Return(keyList)
		documentOwner := privateKeyDocumentOwner{keyResolver: keyResolver}

		result, err := documentOwner.IsOwner(context.Background(), did.MustParseDID("did:nuts:example.com"))
		assert.True(t, result)
		assert.NoError(t, err)
	})
	t.Run("not owned", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		keyResolver := crypto.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().List(gomock.Any()).Return(keyList)
		documentOwner := privateKeyDocumentOwner{keyResolver: keyResolver}

		result, err := documentOwner.IsOwner(context.Background(), did.MustParseDID("did:nuts:voorbeeld.nl"))
		assert.False(t, result)
		assert.NoError(t, err)
	})
}

func Test_privateKeyDocumentOwner_ListOwned(t *testing.T) {
	keyList := []string{
		"did:nuts:example.com#key-1",
		"did:nuts:example.com",
		"",
		"not a DID",
		"did:nuts:another-did.com#key-2",
		"did:nuts:example.com#key-2",
	}
	expected := []did.DID{
		did.MustParseDID("did:nuts:example.com"),
		did.MustParseDID("did:nuts:another-did.com"),
	}
	ctrl := gomock.NewController(t)
	keyResolver := crypto.NewMockKeyResolver(ctrl)
	keyResolver.EXPECT().List(gomock.Any()).Return(keyList)
	documentOwner := privateKeyDocumentOwner{keyResolver: keyResolver}

	result, err := documentOwner.ListOwned(context.Background())

	require.NoError(t, err)
	assert.Equal(t, expected, result)
}
