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
 */

package didsubject

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/require"
	"testing"

	resolver2 "github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
)

func TestResolver_Resolve(t *testing.T) {
	db := testDB(t)

	t.Run("not found", func(t *testing.T) {
		resolver := Resolver{DB: db}
		exampleDID := did.MustParseDID("did:example:123")

		_, _, err := resolver.Resolve(exampleDID, nil)

		assert.ErrorIs(t, err, resolver2.ErrNotFound)
	})
	t.Run("deactivated", func(t *testing.T) {
		exampleDID := did.MustParseDID("did:example:123")
		resolver := Resolver{DB: db}
		sqlDIDDocumentManager := NewDIDDocumentManager(db)
		_, err := sqlDIDDocumentManager.CreateOrUpdate(DID{ID: exampleDID.String()}, nil, nil)
		require.NoError(t, err)

		doc, meta, err := resolver.Resolve(exampleDID, &resolver2.ResolveMetadata{AllowDeactivated: true})

		require.NoError(t, err)
		require.NotNil(t, doc)
		require.NotNil(t, meta)
		assert.True(t, meta.Deactivated)
	})
}
