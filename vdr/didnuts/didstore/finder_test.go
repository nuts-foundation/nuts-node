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

package didstore

import (
	"errors"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestFinder_Find(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		didStore := NewMockStore(ctrl)
		finder := Finder{Store: didStore}
		didStore.EXPECT().Iterate(gomock.Any()).Do(func(arg interface{}) {
			f := arg.(management.DocIterator)
			f(did.Document{}, resolver.DocumentMetadata{})
		})

		docs, err := finder.Find(management.IsActive())

		require.NoError(t, err)
		assert.Len(t, docs, 1)
	})

	t.Run("error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		didStore := NewMockStore(ctrl)
		finder := Finder{Store: didStore}
		didStore.EXPECT().Iterate(gomock.Any()).Return(errors.New("b00m!"))

		_, err := finder.Find(management.IsActive())

		assert.Error(t, err)
	})
}
