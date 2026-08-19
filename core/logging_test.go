/*
 * Copyright (C) 2026 Nuts community
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

package core

import (
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSafeStringer(t *testing.T) {
	t.Run("nil pointer returns nil, does not panic", func(t *testing.T) {
		var uri *ssi.URI

		result := SafeStringer(uri)

		assert.Nil(t, result)
	})
	t.Run("non-nil pointer is returned unchanged", func(t *testing.T) {
		uri, err := ssi.ParseURI("https://example.com")
		require.NoError(t, err)

		result := SafeStringer(uri)

		assert.Equal(t, uri, result)
	})
}
