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

package didservice

import (
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
)

func TestNutsKeyResolver_ResolvePublicKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	docResolver := types.NewMockDocResolver(ctrl)
	keyResolver := NutsKeyResolver{Resolver: docResolver}
	keyCreator := newMockKeyCreator()
	docCreator := Creator{KeyStore: keyCreator}
	doc, _, _ := docCreator.Create(nil, DefaultCreationOptions())

	t.Run("ok by hash", func(t *testing.T) {
		docResolver.EXPECT().Resolve(testDID, gomock.Any()).Do(func(arg0 interface{}, arg1 interface{}) {
			resolveMetadata := arg1.(*types.ResolveMetadata)
			assert.Equal(t, hash.EmptyHash(), *resolveMetadata.SourceTransaction)
		}).Return(doc, nil, nil)

		key, err := keyResolver.ResolvePublicKey(mockKID, []hash.SHA256Hash{hash.EmptyHash()})
		require.NoError(t, err)

		assert.NotNil(t, key)
	})

}
