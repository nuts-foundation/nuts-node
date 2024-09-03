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

package didsubject

import (
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

var sqlDidAlice = orm.DID{ID: alice.String(), Subject: "alice"}

func TestSqlDIDDocumentManager_CreateOrUpdate(t *testing.T) {
	keyUsageFlag := orm.VerificationMethodKeyType(31)
	vm := orm.VerificationMethod{
		ID:       "#1",
		Data:     []byte("{}"),
		KeyTypes: keyUsageFlag,
	}
	service := orm.Service{
		ID:   "#2",
		Data: []byte("{}"),
	}
	sqlDidBob := orm.DID{ID: bob.String(), Subject: "bob"}
	db := testDB(t)

	t.Run("first version", func(t *testing.T) {
		tx := transaction(t, db)
		docManager := NewDIDDocumentManager(tx)

		doc, err := docManager.CreateOrUpdate(sqlDidAlice, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, doc)

		assert.Equal(t, 1, doc.Version)
		assert.Len(t, doc.ID, 36) // uuid v4
		assert.Equal(t, alice.String(), doc.DID.ID)
		assert.Equal(t, "alice", doc.DID.Subject)
		assert.Equal(t, "did:web:example.com:iam:alice", doc.DidID)
	})
	t.Run("with method and services", func(t *testing.T) {
		tx := transaction(t, db)
		docManager := NewDIDDocumentManager(tx)

		doc, err := docManager.CreateOrUpdate(sqlDidBob, []orm.VerificationMethod{vm}, []orm.Service{service})
		require.NoError(t, err)

		require.Len(t, doc.VerificationMethods, 1)
		require.Len(t, doc.Services, 1)
		assert.Len(t, doc.ID, 36) // uuid v4
		assert.Equal(t, []byte("{}"), doc.VerificationMethods[0].Data)
		assert.Equal(t, keyUsageFlag, doc.VerificationMethods[0].KeyTypes)
		assert.Equal(t, []byte("{}"), doc.Services[0].Data)

	})
	t.Run("update", func(t *testing.T) {
		tx := db.Begin()
		docManager := NewDIDDocumentManager(tx)
		_, err := docManager.CreateOrUpdate(sqlDidBob, []orm.VerificationMethod{vm}, []orm.Service{service})
		require.NoError(t, err)
		require.NoError(t, tx.Commit().Error)

		docManager = NewDIDDocumentManager(transaction(t, db))
		require.NoError(t, err)

		doc, err := docManager.CreateOrUpdate(sqlDidBob, []orm.VerificationMethod{vm}, []orm.Service{service})

		assert.Len(t, doc.ID, 36) // uuid v4
		require.Len(t, doc.VerificationMethods, 1)
		require.Len(t, doc.Services, 1)
	})
}

func TestSqlDIDDocumentManager_Latest(t *testing.T) {
	db := testDB(t)
	tx := transaction(t, db)
	docManager := NewDIDDocumentManager(tx)
	keyUsageFlag := orm.VerificationMethodKeyType(orm.AssertionMethodUsage | orm.AuthenticationUsage | orm.CapabilityDelegationUsage | orm.CapabilityInvocationUsage)
	vm := orm.VerificationMethod{
		ID:       "#1",
		Data:     []byte("{}"),
		KeyTypes: keyUsageFlag,
	}
	doc, err := docManager.CreateOrUpdate(sqlDidAlice, []orm.VerificationMethod{vm}, nil)
	require.NoError(t, err)

	t.Run("found", func(t *testing.T) {
		latest, err := docManager.Latest(alice, nil)
		require.NoError(t, err)

		assert.Equal(t, doc.ID, latest.ID)
		require.Len(t, latest.VerificationMethods, 1)
		assert.Equal(t, keyUsageFlag, doc.VerificationMethods[0].KeyTypes)
	})
	t.Run("not found", func(t *testing.T) {
		latest, err := docManager.Latest(did.MustParseDID("did:web:example.com:iam:unknown"), nil)

		assert.Equal(t, gorm.ErrRecordNotFound, err)
		assert.Nil(t, latest)
	})
	t.Run("contains alsoKnownAs", func(t *testing.T) {
		sqlDidBob := orm.DID{ID: bob.String(), Subject: "bob", Aka: []orm.DID{sqlDidAlice}}
		_, err := docManager.CreateOrUpdate(sqlDidBob, nil, nil)
		require.NoError(t, err)

		latest, err := docManager.Latest(bob, nil)
		require.NoError(t, err)

		// in DID
		assert.Len(t, latest.DID.Aka, 2)

		// in did document (from Raw)
		didDoc, err := latest.ToDIDDocument()
		require.NoError(t, err)
		assert.Len(t, didDoc.AlsoKnownAs, 1)
	})
}
