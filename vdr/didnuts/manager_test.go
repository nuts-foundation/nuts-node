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

package didnuts

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"testing"
)

func TestManager_Create(t *testing.T) {
	ctrl := gomock.NewController(t)
	creator := management.NewMockDocCreator(ctrl)
	owner := management.NewMockDocumentOwner(ctrl)
	manager := NewManager(creator, owner)
	creator.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, nil, nil)

	_, _, err := manager.Create(nil, DefaultCreationOptions())

	assert.NoError(t, err)
}

func TestManager_IsOwner(t *testing.T) {
	t.Run("not owned", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		creator := management.NewMockDocCreator(ctrl)
		owner := management.NewMockDocumentOwner(ctrl)
		manager := NewManager(creator, owner)
		owner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)

		actual, err := manager.IsOwner(nil, did.MustParseDID("did:nuts:example.com"))

		assert.NoError(t, err)
		assert.False(t, actual)
	})
	t.Run("owned", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		creator := management.NewMockDocCreator(ctrl)
		owner := management.NewMockDocumentOwner(ctrl)
		manager := NewManager(creator, owner)
		owner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil)

		actual, err := manager.IsOwner(nil, did.MustParseDID("did:nuts:example.com"))

		assert.NoError(t, err)
		assert.True(t, actual)
	})
	t.Run("does not check DIDs other than did:nuts", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		creator := management.NewMockDocCreator(ctrl)
		owner := management.NewMockDocumentOwner(ctrl)
		manager := NewManager(creator, owner)

		actual, err := manager.IsOwner(nil, did.MustParseDID("did:web:example.com"))

		assert.NoError(t, err)
		assert.False(t, actual)
	})
}

func TestManager_ListOwned(t *testing.T) {
	t.Run("no owned dids", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		creator := management.NewMockDocCreator(ctrl)
		owner := management.NewMockDocumentOwner(ctrl)
		manager := NewManager(creator, owner)
		owner.EXPECT().ListOwned(gomock.Any()).Return(nil, nil)

		actual, err := manager.ListOwned(nil)

		assert.NoError(t, err)
		assert.Empty(t, actual)
	})
	expectedDID := did.MustParseDID("did:nuts:example.com")
	t.Run("some owned dids", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		creator := management.NewMockDocCreator(ctrl)
		owner := management.NewMockDocumentOwner(ctrl)
		manager := NewManager(creator, owner)
		owner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{expectedDID}, nil)

		actual, err := manager.ListOwned(nil)

		assert.NoError(t, err)
		assert.Len(t, actual, 1)
	})
	t.Run("filters DIDs other than did:nuts", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		creator := management.NewMockDocCreator(ctrl)
		owner := management.NewMockDocumentOwner(ctrl)
		manager := NewManager(creator, owner)
		owner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{
			expectedDID,
			did.MustParseDID("did:web:example.com"),
		}, nil)

		actual, err := manager.ListOwned(nil)

		assert.NoError(t, err)
		assert.Len(t, actual, 1)
		assert.Equal(t, expectedDID, actual[0])
	})
}

func TestManager_Resolve(t *testing.T) {
	_, _, err := Manager{}.Resolve(did.DID{}, nil)
	assert.EqualError(t, err, "Resolve() is not supported for did:nuts")
}

func TestManager_CreateService(t *testing.T) {
	_, err := Manager{}.CreateService(nil, did.DID{}, did.Service{})
	assert.EqualError(t, err, "CreateService() is not supported for did:nuts")
}

func TestManager_DeleteService(t *testing.T) {
	err := Manager{}.DeleteService(nil, did.DID{}, ssi.MustParseURI("https://example.com"))
	assert.EqualError(t, err, "DeleteService() is not supported for did:nuts")
}

func TestManager_UpdateService(t *testing.T) {
	_, err := Manager{}.UpdateService(nil, did.DID{}, ssi.MustParseURI("https://example.com"), did.Service{})
	assert.EqualError(t, err, "UpdateService() is not supported for did:nuts")
}
