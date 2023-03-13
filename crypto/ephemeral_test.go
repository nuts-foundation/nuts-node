/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

package crypto

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestNewEphemeralKey(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		key, err := NewEphemeralKey(StringNamingFunc("kid"))

		require.NoError(t, err)

		assert.NotNil(t, key)
		assert.NotNil(t, key.Public())
		assert.Equal(t, "kid", key.KID())
	})

	t.Run("error", func(t *testing.T) {
		_, err := NewEphemeralKey(ErrorNamingFunc(errors.New("b00m!")))

		assert.EqualError(t, err, "b00m!")
	})
}
