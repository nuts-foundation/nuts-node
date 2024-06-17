package sql

import (
	"github.com/nuts-foundation/go-did/did"
	"gorm.io/gorm"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSqlDIDDocumentManager_AddVersion(t *testing.T) {
	vm := SqlVerificationMethod{
		ID:   "#1",
		Data: []byte("{}"),
	}
	service := SqlService{
		ID:   "#2",
		Data: []byte("{}"),
	}
	db := testDB(t)

	t.Run("first version", func(t *testing.T) {
		tx := transaction(t, db)
		didManager := NewDIDManager(tx)
		added, err := didManager.Add("alice", alice)
		require.NoError(t, err)
		docManager := NewDIDDocumentManager(tx)

		doc, err := docManager.AddVersion(added[0], nil, nil)
		require.NoError(t, err)
		require.NotNil(t, doc)

		assert.Equal(t, 1, doc.Version)
		assert.Equal(t, "did:web:example.com:iam:alice#1", doc.ID)
		assert.Equal(t, alice.String(), doc.DID.ID)
		assert.Equal(t, "alice", doc.DID.Subject)
	})
	t.Run("with method and services", func(t *testing.T) {
		tx := transaction(t, db)
		didManager := NewDIDManager(tx)
		added, err := didManager.Add("bob", bob)
		require.NoError(t, err)
		docManager := NewDIDDocumentManager(tx)
		vm := SqlVerificationMethod{
			ID:            "#1",
			DIDDocumentID: added[0].ID,
			Data:          []byte("{}"),
		}
		service := SqlService{
			ID:            "#2",
			DIDDocumentID: added[0].ID,
			Data:          []byte("{}"),
		}

		doc, err := docManager.AddVersion(added[0], []SqlVerificationMethod{vm}, []SqlService{service})
		require.NoError(t, err)

		assert.Len(t, doc.VerificationMethods, 1)
		assert.Len(t, doc.Services, 1)
	})
	t.Run("update", func(t *testing.T) {
		tx := db.Begin()
		docManager := NewDIDDocumentManager(tx)
		didManager := NewDIDManager(tx)
		added, err := didManager.Add("bob", bob)
		require.NoError(t, err)
		_, err = docManager.AddVersion(added[0], []SqlVerificationMethod{vm}, []SqlService{service})
		require.NoError(t, err)
		require.NoError(t, tx.Commit().Error)

		docManager = NewDIDDocumentManager(transaction(t, db))
		require.NoError(t, err)

		doc, err := docManager.AddVersion(added[0], []SqlVerificationMethod{vm}, []SqlService{service})

		assert.Equal(t, "did:web:example.com:iam:bob#2", doc.ID)
		require.Len(t, doc.VerificationMethods, 1)
		assert.Equal(t, "did:web:example.com:iam:bob#2", doc.VerificationMethods[0].DIDDocumentID)
		require.Len(t, doc.Services, 1)
		assert.Equal(t, "did:web:example.com:iam:bob#2", doc.Services[0].DIDDocumentID)
	})
}

func TestSqlDIDDocumentManager_Latest(t *testing.T) {
	db := testDB(t)
	tx := transaction(t, db)
	didManager := NewDIDManager(tx)
	docManager := NewDIDDocumentManager(tx)
	added, err := didManager.Add("alice", alice)
	require.NoError(t, err)
	doc, err := docManager.AddVersion(added[0], nil, nil)
	require.NoError(t, err)

	t.Run("found", func(t *testing.T) {
		latest, err := docManager.Latest(alice)
		require.NoError(t, err)

		assert.Equal(t, doc.ID, latest.ID)
	})
	t.Run("not found", func(t *testing.T) {

		latest, err := docManager.Latest(did.MustParseDID("did:web:example.com:iam:unknown"))

		assert.Equal(t, gorm.ErrRecordNotFound, err)
		assert.Nil(t, latest)
	})
}
