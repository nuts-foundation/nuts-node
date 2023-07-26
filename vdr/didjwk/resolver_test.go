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
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An example did:jwk from https://github.com/quartzjer/did-jwk/blob/6520a0edc8fa8f37c09af99efe841d54c3ca3b3b/spec.md
const b64EncodedTestJWK = `eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9`

func TestResolver_Resolve(t *testing.T) {
	var baseDID did.DID
	resolver := &Resolver{}

	baseDID = did.MustParseDID("did:jwk:" + b64EncodedTestJWK)

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

	t.Run("base64 encoded non-JSON fails", func(t *testing.T) {
		id := did.MustParseDIDURL("did:jwk:eyJqc29uIjogInRoaXMgdmFsaWQgSlNPTiBpcyBub3QgYSBKV0sifQ")
		doc, md, err := resolver.Resolve(id, nil)

		require.ErrorContains(t, err, "invalid key type from JSON")
		assert.Nil(t, md)
		assert.Nil(t, doc)
	})
}
