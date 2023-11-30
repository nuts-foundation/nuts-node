package didweb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"testing"
)

var testDID = did.MustParseDID("did:web:example.com")

func Test_sqlStore_create(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	store := &sqlStore{db: storageEngine.GetSQLDatabase()}
	vm1 := testVerificationMethod(t, testDID)
	vm2 := testVerificationMethod(t, testDID)

	t.Run("multiple verification methods", func(t *testing.T) {
		resetStore(t, store.db)

		err := store.create(testDID, vm1, vm2)
		require.NoError(t, err)

		verificationMethods, err := store.get(testDID)
		require.NoError(t, err)
		require.Len(t, verificationMethods, 2)
		require.JSONEq(t, toJSON(vm1), toJSON(verificationMethods[0]))
		require.JSONEq(t, toJSON(vm2), toJSON(verificationMethods[1]))
	})
	t.Run("single verification method", func(t *testing.T) {
		resetStore(t, store.db)

		err := store.create(testDID, vm1)
		require.NoError(t, err)

		verificationMethods, err := store.get(testDID)
		require.NoError(t, err)
		require.Len(t, verificationMethods, 1)
		require.JSONEq(t, toJSON(vm1), toJSON(verificationMethods[0]))
	})
	t.Run("no verification methods", func(t *testing.T) {
		resetStore(t, store.db)

		err := store.create(testDID)
		require.NoError(t, err)

		verificationMethods, err := store.get(testDID)
		require.NoError(t, err)
		require.Len(t, verificationMethods, 0)
	})
}

func Test_sqlStore_get(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	store := &sqlStore{db: storageEngine.GetSQLDatabase()}

	t.Run("DID does not exist", func(t *testing.T) {
		resetStore(t, store.db)

		vms, err := store.get(testDID)
		require.ErrorIs(t, err, resolver.ErrNotFound)
		require.Nil(t, vms, 0)
	})
}

func resetStore(t *testing.T, db *gorm.DB) {
	underlyingDB, err := db.DB()
	require.NoError(t, err)
	// related tables are emptied due to on-delete-cascade clause
	_, err = underlyingDB.Exec("DELETE FROM vdr_didweb_verificationmethod")
	require.NoError(t, err)
	_, err = underlyingDB.Exec("DELETE FROM vdr_didweb")
	require.NoError(t, err)
}

func testVerificationMethod(t *testing.T, owner did.DID) did.VerificationMethod {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid := did.DIDURL{
		DID:      owner,
		Fragment: uuid.NewString(),
	}
	result, err := did.NewVerificationMethod(kid, ssi.JsonWebKey2020, owner, privateKey.PublicKey)
	require.NoError(t, err)
	return *result
}

func toJSON(v interface{}) string {
	result, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(result)
}
