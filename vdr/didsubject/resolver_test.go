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
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolver_Resolve(t *testing.T) {
	exampleDID := did.MustParseDID("did:example:123")
	verificationMethod := orm.VerificationMethod{
		ID:       "did:example:123#1",
		KeyTypes: 31,
		Data:     []byte("{}"),
	}

	t.Run("ok", func(t *testing.T) {
		db := testDB(t)
		sqlDIDDocumentManager := NewDIDDocumentManager(db)
		dbResolver := Resolver{DB: db}
		_, err := sqlDIDDocumentManager.CreateOrUpdate(orm.DID{ID: exampleDID.String()}, []orm.VerificationMethod{verificationMethod}, nil)
		require.NoError(t, err)

		doc, meta, err := dbResolver.Resolve(exampleDID, nil)

		require.NoError(t, err)
		require.NotNil(t, doc)
		require.NotNil(t, meta)
		assert.Equal(t, exampleDID.String(), doc.ID.String())
	})
	t.Run("not found with resolve time", func(t *testing.T) {
		db := testDB(t)
		before := time.Now().Add(-time.Hour)
		sqlDIDDocumentManager := NewDIDDocumentManager(db)
		dbResolver := Resolver{DB: db}
		_, err := sqlDIDDocumentManager.CreateOrUpdate(orm.DID{ID: exampleDID.String()}, []orm.VerificationMethod{verificationMethod}, nil)
		require.NoError(t, err)

		_, _, err = dbResolver.Resolve(exampleDID, &resolver.ResolveMetadata{ResolveTime: &before})

		assert.Equal(t, resolver.ErrNotFound, err)
	})
	t.Run("not found", func(t *testing.T) {
		db := testDB(t)
		dbResolver := Resolver{DB: db}

		_, _, err := dbResolver.Resolve(exampleDID, nil)

		assert.ErrorIs(t, err, resolver.ErrNotFound)
	})
	t.Run("allowed deactivated", func(t *testing.T) {
		db := testDB(t)
		sqlDIDDocumentManager := NewDIDDocumentManager(db)
		dbResolver := Resolver{DB: db}
		_, err := sqlDIDDocumentManager.CreateOrUpdate(orm.DID{ID: exampleDID.String()}, nil, nil)
		require.NoError(t, err)

		doc, meta, err := dbResolver.Resolve(exampleDID, &resolver.ResolveMetadata{AllowDeactivated: true})

		require.NoError(t, err)
		require.NotNil(t, doc)
		require.NotNil(t, meta)
		assert.True(t, meta.Deactivated)
	})
	t.Run("deactivated", func(t *testing.T) {
		db := testDB(t)
		dbResolver := Resolver{DB: db}
		sqlDIDDocumentManager := NewDIDDocumentManager(db)
		_, err := sqlDIDDocumentManager.CreateOrUpdate(orm.DID{ID: exampleDID.String()}, nil, nil)
		require.NoError(t, err)

		_, _, err = dbResolver.Resolve(exampleDID, nil)

		assert.Equal(t, resolver.ErrDeactivated, err)
	})
}
