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

package didjwk

import (
	"encoding/base64"
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolver_Resolve(t *testing.T) {
	var baseDID did.DID
	resolver := &Resolver{}

	baseDID = did.MustParseDID("did:jwk:" + b64EncodedCanonicalJWK)

	t.Run("resolve did:jwk", func(t *testing.T) {
		doc, md, err := resolver.Resolve(baseDID, nil)

		require.NoError(t, err)
		assert.NotNil(t, md)
		require.NotNil(t, doc)
		assert.Equal(t, baseDID, doc.ID)
	})

	t.Run("resolve DID JWK URL", func(t *testing.T) {
		doc, md, err := resolver.Resolve(baseDID, nil)

		require.NoError(t, err)
		assert.NotNil(t, md)
		require.NotNil(t, doc)
		assert.Equal(t, baseDID, doc.ID)
	})

	t.Run("Invalid base64 data fails", func(t *testing.T) {
		id := did.MustParseDIDURL(baseDID.String() + ":invalid-base64-data")
		doc, md, err := resolver.Resolve(id, nil)

		require.ErrorContains(t, err, "illegal base64 data")
		assert.Nil(t, md)
		assert.Nil(t, doc)
	})

	t.Run("base64 encoded non-JSON fails", func(t *testing.T) {
		id := did.MustParseDIDURL("did:jwk:SSBhbSBub3QgYSBqd2s")
		doc, md, err := resolver.Resolve(id, nil)

		require.ErrorContains(t, err, "failed to unmarshal JSON")
		assert.Nil(t, md)
		assert.Nil(t, doc)
	})

	t.Run("base64+JSON encoded non-JWK fails", func(t *testing.T) {
		id := did.MustParseDIDURL("did:jwk:eyJqc29uIjogInRoaXMgdmFsaWQgSlNPTiBpcyBub3QgYSBKV0sifQ")
		doc, md, err := resolver.Resolve(id, nil)

		require.ErrorContains(t, err, "invalid key type from JSON")
		assert.Nil(t, md)
		assert.Nil(t, doc)
	})

	t.Run("DID JWK with private key fails", func(t *testing.T) {
		testFunc := func(json string) func(t *testing.T) {
			return func(t *testing.T) {
				id := did.MustParseDIDURL("did:jwk:" + base64.RawStdEncoding.EncodeToString([]byte(json)))
				doc, md, err := resolver.Resolve(id, nil)

				require.ErrorContains(t, err, "private keys are forbidden in DID JWK")
				assert.Nil(t, md)
				assert.Nil(t, doc)
			}
		}

		t.Run("RSA2048", testFunc(rsa2048JWKWithPrivateKey))
		t.Run("RSA4096", testFunc(rsa4096JWKWithPrivateKey))
		t.Run("EC256", testFunc(ec256JWKWithPrivateKey))
		t.Run("EC384", testFunc(ec384JWKWithPrivateKey))
		t.Run("EC512", testFunc(ec521JWKWithPrivateKey))
	})

}
