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
	"context"
	"github.com/nuts-foundation/go-did/did"
)

var rootDID = did.MustParseDID("did:web:example.com")

const tenantPath = "iam"

var subjectDID = did.MustParseDID("did:web:example.com:iam:1234")
var ctx = context.Background()

//

//
//func TestManager_IsOwner(t *testing.T) {
//	storageEngine := storage.NewTestStorageEngine(t)
//	require.NoError(t, storageEngine.Start())
//
//	t.Run("not owned (empty store)", func(t *testing.T) {
//		db := testDB(t)
//		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)
//
//		owned, err := m.IsOwner(audit.TestContext(), subjectDID)
//		require.NoError(t, err)
//		assert.False(t, owned)
//	})
//	t.Run("not owned (other DID)", func(t *testing.T) {
//		db := testDB(t)
//		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)
//		_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
//		require.NoError(t, err)
//
//		owned, err := m.IsOwner(audit.TestContext(), subjectDID)
//		require.NoError(t, err)
//		assert.False(t, owned)
//	})
//	t.Run("owned", func(t *testing.T) {
//		db := testDB(t)
//		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)
//		document, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
//		require.NoError(t, err)
//
//		owned, err := m.IsOwner(audit.TestContext(), document.ID)
//		require.NoError(t, err)
//		assert.True(t, owned)
//	})
//}
//
//func TestManager_ListOwned(t *testing.T) {
//	storageEngine := storage.NewTestStorageEngine(t)
//	require.NoError(t, storageEngine.Start())
//
//	t.Run("empty store", func(t *testing.T) {
//		db := testDB(t)
//		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)
//
//		dids, err := m.ListOwned(audit.TestContext())
//		require.NoError(t, err)
//		assert.Empty(t, dids)
//	})
//	t.Run("single DID", func(t *testing.T) {
//		db := testDB(t)
//		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)
//		document, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
//		require.NoError(t, err)
//
//		dids, err := m.ListOwned(audit.TestContext())
//		require.NoError(t, err)
//		assert.Equal(t, []did.DID{document.ID}, dids)
//	})
//	t.Run("multiple DIDs", func(t *testing.T) {
//		db := testDB(t)
//		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)
//		document1, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
//		require.NoError(t, err)
//		document2, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
//		require.NoError(t, err)
//
//		dids, err := m.ListOwned(audit.TestContext())
//		require.NoError(t, err)
//		assert.ElementsMatch(t, []did.DID{document1.ID, document2.ID}, dids)
//	})
//}
//
//func TestManager_Resolve(t *testing.T) {
//	storageEngine := storage.NewTestStorageEngine(t)
//	require.NoError(t, storageEngine.Start())
//
//	t.Run("not found", func(t *testing.T) {
//		db := testDB(t)
//		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)
//
//		document, _, err := m.Resolve(did.MustParseDID("did:web:example.com:1234"), nil)
//		require.ErrorIs(t, err, resolver.ErrNotFound)
//		assert.Nil(t, document)
//	})
//	t.Run("ok", func(t *testing.T) {
//		db := testDB(t)
//		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)
//		document, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
//		require.NoError(t, err)
//		expected, _ := document.MarshalJSON()
//
//		resolvedDocument, _, err := m.Resolve(document.ID, nil)
//		require.NoError(t, err)
//		actual, _ := resolvedDocument.MarshalJSON()
//		assert.JSONEq(t, string(expected), string(actual))
//	})
//}
//
//func TestManager_Services(t *testing.T) {
//	newManager := func(t *testing.T) *Manager {
//		db := testDB(t)
//		tx := db.Begin()
//		didDocumentManager := sql.NewDIDDocumentManager(tx)
//		m := NewManager(rootDID, tenantPath, nil, db)
//		sqlDid := sql.DID{ID: subjectDID.String(), Subject: "uuid"}
//		_, err := didDocumentManager.CreateOrUpdate(sqlDid, nil, nil)
//		require.NoError(t, err)
//		tx.Commit()
//		return m
//	}
//
//	t.Run("create", func(t *testing.T) {
//		t.Run("with ID", func(t *testing.T) {
//			m := newManager(t)
//
//			expected := did.Service{
//				ID:              ssi.MustParseURI(subjectDID.String() + "#api"),
//				Type:            "API",
//				ServiceEndpoint: "https://example.com/api",
//			}
//			actual, err := m.CreateService(ctx, subjectDID, expected)
//
//			require.NoError(t, err)
//			require.Equal(t, expected, *actual)
//			didDocumentManager := sql.NewDIDDocumentManager(m.db)
//			document, err := didDocumentManager.Latest(subjectDID)
//			require.NoError(t, err)
//			require.Len(t, document.Services, 1)
//			assert.Equal(t, expected.ID.String(), document.Services[0].ID)
//
//		})
//		t.Run("random ID", func(t *testing.T) {
//			m := newManager(t)
//
//			input := did.Service{
//				Type:            "API",
//				ServiceEndpoint: "https://example.com/api",
//			}
//
//			actual, err := m.CreateService(ctx, subjectDID, input)
//
//			require.NoError(t, err)
//			assert.NotEqual(t, "", actual.ID.Fragment)
//			didDocumentManager := sql.NewDIDDocumentManager(m.db)
//			document, err := didDocumentManager.Latest(subjectDID)
//			require.NoError(t, err)
//			require.Len(t, document.Services, 1)
//			assert.Equal(t, actual.ID.String(), document.Services[0].ID)
//		})
//	})
//	t.Run("update", func(t *testing.T) {
//		t.Run("ID not set", func(t *testing.T) {
//			m := newManager(t)
//
//			serviceID := ssi.MustParseURI(subjectDID.String() + "#api")
//			input := did.Service{}
//			expected := did.Service{
//				ID: serviceID,
//			}
//			actual, err := m.UpdateService(ctx, subjectDID, serviceID, input)
//
//			require.NoError(t, err)
//			assert.Equal(t, expected, *actual)
//
//			didDocumentManager := sql.NewDIDDocumentManager(m.db)
//			document, err := didDocumentManager.Latest(subjectDID)
//			require.NoError(t, err)
//			require.Len(t, document.Services, 1)
//			assert.Equal(t, expected.ID.String(), document.Services[0].ID)
//		})
//		t.Run("ID is set", func(t *testing.T) {
//			m := newManager(t)
//
//			serviceID := ssi.MustParseURI(subjectDID.String() + "#api")
//			input := did.Service{
//				ID: serviceID,
//			}
//			actual, err := m.UpdateService(ctx, subjectDID, serviceID, input)
//
//			require.NoError(t, err)
//			assert.Equal(t, input, *actual)
//		})
//	})
//	t.Run("Delete", func(t *testing.T) {
//		m := newManager(t)
//
//		expected := did.Service{
//			ID:              ssi.MustParseURI(subjectDID.String() + "#api"),
//			Type:            "API",
//			ServiceEndpoint: "https://example.com/api",
//		}
//		_, err := m.CreateService(ctx, subjectDID, expected)
//		require.NoError(t, err)
//
//		err = m.DeleteService(ctx, subjectDID, expected.ID)
//		require.NoError(t, err)
//
//		didDocumentManager := sql.NewDIDDocumentManager(m.db)
//		document, err := didDocumentManager.Latest(subjectDID)
//		require.NoError(t, err)
//		assert.Len(t, document.Services, 0)
//	})
//}
//
