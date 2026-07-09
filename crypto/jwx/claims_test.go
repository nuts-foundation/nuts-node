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

package jwx

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeadersAsMap(t *testing.T) {
	t.Run("preserves members and represents a null-valued member as nil", func(t *testing.T) {
		headers := jws.NewHeaders()
		require.NoError(t, headers.Set("string-member", "value"))
		require.NoError(t, headers.Set("null-member", nil))
		require.Contains(t, headers.Keys(), "null-member") // sanity: the null member is actually present

		m := HeadersAsMap(headers)

		assert.Equal(t, "value", m["string-member"])
		// A per-field Get errors on the null member; HeadersAsMap must instead store nil.
		nilValue, present := m["null-member"]
		assert.True(t, present, "null-valued member must be present in the map")
		assert.Nil(t, nilValue)
	})
	t.Run("keeps the concrete Go type of a rich member (like x5c)", func(t *testing.T) {
		headers := jws.NewHeaders()
		require.NoError(t, headers.Set("rich-member", []string{"a", "b"}))

		m := HeadersAsMap(headers)

		// A JSON round-trip (jwx.AsMap) would flatten this to []interface{}; HeadersAsMap keeps
		// the concrete []string, which is what callers of rich headers such as x5c rely on.
		assert.IsType(t, []string{}, m["rich-member"])
	})
}
