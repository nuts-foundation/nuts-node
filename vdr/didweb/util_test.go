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
	did2 "github.com/nuts-foundation/go-did/did"
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
	t.Run("empty part", func(t *testing.T) {
		requestUrl, _ := url.Parse("https://localhost/iam/5/")
		result, err := URLToDID(*requestUrl)

		require.NoError(t, err)
		assert.Equal(t, "did:web:localhost:iam:5", result.String())
	})
	t.Run("encoded path", func(t *testing.T) {
		requestUrl, _ := url.Parse("https://localhost/x/y%2Fz/did.json")
		result, err := URLToDID(*requestUrl)

		require.NoError(t, err)
		assert.Equal(t, "did:web:localhost:x:y%2Fz", result.String())
	})
}

func TestDIDToURL(t *testing.T) {
	t.Run("well-known", func(t *testing.T) {
		did := did2.MustParseDID("did:web:localhost")
		expected, _ := url.Parse("https://localhost")
		result, err := DIDToURL(did)

		require.NoError(t, err)
		assert.Equal(t, expected, result)
	})
	t.Run("with subpath", func(t *testing.T) {
		did := did2.MustParseDID("did:web:localhost:alice%2Band%2Bbob:path")
		expected, _ := url.Parse("https://localhost/alice+and+bob/path")
		result, err := DIDToURL(did)

		require.NoError(t, err)
		assert.Equal(t, expected, result)
	})
	t.Run("domain, port and subpath", func(t *testing.T) {
		did := did2.MustParseDID("did:web:localhost%3A3000:alice%2Band%2Bbob:path")
		expected, _ := url.Parse("https://localhost:3000/alice+and+bob/path")
		result, err := DIDToURL(did)

		require.NoError(t, err)
		assert.Equal(t, expected, result)
	})
	t.Run("encoded path", func(t *testing.T) {
		did := did2.MustParseDID("did:web:localhost:x:y%2Fz")
		expected, _ := url.Parse("https://localhost/x/y%2Fz")
		result, err := DIDToURL(did)

		require.NoError(t, err)
		assert.Equal(t, expected, result)
	})
	t.Run("encoded illegal traversal path", func(t *testing.T) {
		did := did2.MustParseDID("did:web:localhost:x:y:%2E%2E:z")
		expected, _ := url.Parse("https://localhost/x/y/%2E%2E/z")
		result, err := DIDToURL(did)

		require.NoError(t, err)
		assert.Equal(t, expected, result)
	})
	t.Run("contains empty paths (every : must be followed by a path)", func(t *testing.T) {
		did := did2.MustParseDID("did:web:example.com:sub::path")
		_, err := DIDToURL(did)

		assert.EqualError(t, err, "invalid did:web: contains empty path elements")
	})
	t.Run("ends with empty path (every : must be followed by a path)", func(t *testing.T) {
		did := did2.MustParseDID("did:web:example.com:")

		_, err := DIDToURL(did)

		assert.EqualError(t, err, "invalid did:web: contains empty path elements")
	})
	t.Run("ID must be just domain (contains encoded path)", func(t *testing.T) {
		did := did2.MustParseDID("did:web:example.com%2Fpath")

		_, err := DIDToURL(did)

		assert.EqualError(t, err, "invalid did:web: illegal characters in domain name")
	})
	t.Run("ID must be just domain, with port (contains encoded path)", func(t *testing.T) {
		did := did2.MustParseDID("did:web:example.com%3A443%2Fpath")

		_, err := DIDToURL(did)

		assert.EqualError(t, err, "invalid did:web: illegal characters in domain name")
	})
	t.Run("ID can't be an IP address (IPv4)", func(t *testing.T) {
		did := did2.MustParseDID("did:web:127.0.0.1")

		_, err := DIDToURL(did)

		assert.EqualError(t, err, "invalid did:web: ID must be a domain name, not IP address")
	})
	t.Run("ID can't be an IP address (IPv6)", func(t *testing.T) {
		// did.Parse() rejects IPv6 addresses in DIDs, so we have to "build" it
		did := did2.DID{
			Method: MethodName,
			ID:     "[%3A%3A1]",
		}

		_, err := DIDToURL(did)

		assert.EqualError(t, err, "invalid did:web: ID must be a domain name, not IP address")
	})
}
