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

	baseDID = did.MustParseDIDURL("did:jwk:" + b64EncodedTestJWK + "#0")

	t.Run("resolve did:jwk", func(t *testing.T) {
		doc, md, err := resolver.Resolve(baseDID, nil)

		require.NoError(t, err)
		assert.NotNil(t, md)
		require.NotNil(t, doc)
		assert.Equal(t, baseDID, doc.ID)
	})

	t.Run("resolve DID JWK URL", func(t *testing.T) {
		id := did.MustParseDIDURL(baseDID.String())
		doc, md, err := resolver.Resolve(id, nil)

		require.NoError(t, err)
		assert.NotNil(t, md)
		require.NotNil(t, doc)
		assert.Equal(t, baseDID, doc.ID)
	})

	/*
	// TODO: Is this relevant for did:jwk?
	t.Run("ID in document does not match DID being resolved", func(t *testing.T) {
		id := did.MustParseDIDURL(baseDID.String() + ":invalid-id-in-document")
		doc, md, err := resolver.Resolve(id, nil)

		require.ErrorContains(t, err, "did:jwk document ID mismatch")
		assert.Nil(t, md)
		assert.Nil(t, doc)
	})
	*/
}
