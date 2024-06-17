package sql

import (
	"github.com/nuts-foundation/go-did/did"
	"testing"

	"github.com/magiconair/properties/assert"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

var (
	alice = did.MustParseDID("did:web:example.com:iam:alice")
	bob   = did.MustParseDID("did:web:example.com:iam:bob")
)

func testDB(t *testing.T) *gorm.DB {
	//logrus.SetLevel(logrus.TraceLevel)
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	db := storageEngine.GetSQLDatabase()
	return db
}
func transaction(t *testing.T, db *gorm.DB) *gorm.DB {
	tx := db.Begin()
	t.Cleanup(func() {
		tx.Rollback()
	})
	return tx
}

func assertLen(t *testing.T, tx *gorm.DB, length int) {
	count := int64(0)
	err := tx.Table("did").Count(&count).Error
	require.NoError(t, err)
	assert.Equal(t, count, int64(length))
}
