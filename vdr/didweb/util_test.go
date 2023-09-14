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

package didweb

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
)

func TestUrlToDid(t *testing.T) {
	t.Run("well-known", func(t *testing.T) {
		requestUrl, _ := url.Parse("https://localhost/.well-known/did.json")
		result, err := URLToDID(*requestUrl)

		require.NoError(t, err)
		assert.Equal(t, "did:web:localhost", result.String())
	})
	t.Run("with subpath", func(t *testing.T) {
		requestUrl, _ := url.Parse("https://localhost/alice+and+bob/path/did.json")
		result, err := URLToDID(*requestUrl)

		require.NoError(t, err)
		assert.Equal(t, "did:web:localhost:alice%2Band%2Bbob:path", result.String())
	})
	t.Run("domain, port and subpath", func(t *testing.T) {
		requestUrl, _ := url.Parse("https://localhost:3000/alice+and+bob/path/did.json")
		result, err := URLToDID(*requestUrl)

		require.NoError(t, err)
		assert.Equal(t, "did:web:localhost%3A3000:alice%2Band%2Bbob:path", result.String())
	})
	t.Run("no did.json", func(t *testing.T) {
		requestUrl, _ := url.Parse("https://localhost/something-else")
		result, err := URLToDID(*requestUrl)

		require.NoError(t, err)
		assert.Equal(t, "did:web:localhost:something-else", result.String())
	})
	t.Run("encoded path", func(t *testing.T) {
		requestUrl, _ := url.Parse("https://localhost/x/y%2Fz/did.json")
		result, err := URLToDID(*requestUrl)

		require.NoError(t, err)
		assert.Equal(t, "did:web:localhost:x:y%2Fz", result.String())
	})
}
