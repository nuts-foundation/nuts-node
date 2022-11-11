/*
 * Nuts node
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

package jsonld

import (
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseScalar(t *testing.T) {
	t.Run("ok - string", func(t *testing.T) {
		s, err := ParseScalar("string")

		require.NoError(t, err)
		assert.Equal(t, "string", s.Value())
	})

	t.Run("ok - number", func(t *testing.T) {
		s, err := ParseScalar(1.0)

		require.NoError(t, err)
		assert.Equal(t, 1.0, s.Value())
	})

	t.Run("ok - true", func(t *testing.T) {
		s, err := ParseScalar(true)

		require.NoError(t, err)
		assert.Equal(t, true, s.Value())
	})

	t.Run("ok - false", func(t *testing.T) {
		s, err := ParseScalar(false)

		require.NoError(t, err)
		assert.Equal(t, false, s.Value())
	})

	t.Run("err - unsupported", func(t *testing.T) {
		_, err := ParseScalar(struct{}{})

		assert.Equal(t, ErrInvalidValue, err)
	})
}

func TestScalar_String(t *testing.T) {
	t.Run("ok - string", func(t *testing.T) {
		s := StringScalar("string")

		assert.Equal(t, "string", s.String())
	})

	t.Run("ok - number", func(t *testing.T) {
		s := Float64Scalar(1.0)

		assert.Equal(t, "1.000000", s.String())
	})

	t.Run("ok - negative number", func(t *testing.T) {
		s := Float64Scalar(-1.0)

		assert.Equal(t, "-1.000000", s.String())
	})

	t.Run("ok - true", func(t *testing.T) {
		s := BoolScalar(true)

		assert.Equal(t, "true", s.String())
	})

	t.Run("ok - false", func(t *testing.T) {
		s := BoolScalar(false)

		assert.Equal(t, "false", s.String())
	})
}
