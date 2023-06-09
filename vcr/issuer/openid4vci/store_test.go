package openid4vci

import (
	"context"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"path"
	"testing"
	"time"
)

const refType = "ref-type"
const ref = "ref-value"

func Test_stoabsStore_DeleteReference(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		store := createStore(t)
		expected := Flow{
			ID:     "flow-id",
			Expiry: futureExpiry(),
		}
		err := store.Store(context.Background(), expected)
		assert.NoError(t, err)
		err = store.StoreReference(context.Background(), expected.ID, refType, ref, futureExpiry())
		assert.NoError(t, err)

		err = store.DeleteReference(context.Background(), refType, ref)
		assert.NoError(t, err)

		// Now it can't be found anymore
		actual, err := store.FindByReference(context.Background(), refType, ref)
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
	t.Run("unknown reference", func(t *testing.T) {
		store := createStore(t)

		err := store.DeleteReference(context.Background(), refType, ref)

		assert.NoError(t, err)
	})
}

func Test_stoabsStore_FindByReference(t *testing.T) {
	t.Run("reference already exists", func(t *testing.T) {
		store := createStore(t)
		expected := Flow{
			ID:     "flow-id",
			Expiry: futureExpiry(),
		}
		err := store.Store(context.Background(), expected)
		assert.NoError(t, err)

		err = store.StoreReference(context.Background(), expected.ID, refType, ref, futureExpiry())
		assert.NoError(t, err)
		err = store.StoreReference(context.Background(), expected.ID, refType, ref, futureExpiry())

		assert.EqualError(t, err, "reference already exists")
	})
	t.Run("invalid reference", func(t *testing.T) {
		store := createStore(t)

		err := store.StoreReference(context.Background(), "unknown", refType, "", futureExpiry())

		assert.EqualError(t, err, "invalid reference")
	})
	t.Run("unknown flow", func(t *testing.T) {
		store := createStore(t)

		err := store.StoreReference(context.Background(), "unknown", refType, ref, futureExpiry())

		assert.EqualError(t, err, "OAuth2 flow with this ID does not exist")
	})
	t.Run("reference has expired", func(t *testing.T) {
		store := createStore(t)
		expected := Flow{
			ID:     "flow-id",
			Expiry: futureExpiry(),
		}

		err := store.Store(context.Background(), expected)
		assert.NoError(t, err)
		// We need a reference to resolve it
		err = store.StoreReference(context.Background(), expected.ID, refType, ref, time.Now().Add(-time.Hour))
		assert.NoError(t, err)

		actual, err := store.FindByReference(context.Background(), refType, ref)
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
}

func Test_stoabsStore_Store(t *testing.T) {
	t.Run("write, then read", func(t *testing.T) {
		store := createStore(t)
		expected := Flow{
			ID:     "flow-id",
			Expiry: futureExpiry(),
		}

		err := store.Store(context.Background(), expected)
		assert.NoError(t, err)
		// We need a reference to resolve it
		err = store.StoreReference(context.Background(), expected.ID, refType, ref, futureExpiry())
		assert.NoError(t, err)

		actual, err := store.FindByReference(context.Background(), refType, ref)
		assert.NoError(t, err)
		assert.Equal(t, expected, *actual)
	})
	t.Run("already exists", func(t *testing.T) {
		store := createStore(t)
		expected := Flow{
			ID:     "flow-id",
			Expiry: futureExpiry(),
		}

		err := store.Store(context.Background(), expected)
		assert.NoError(t, err)
		err = store.Store(context.Background(), expected)

		assert.EqualError(t, err, "OAuth2 flow with this ID already exists")
	})
	t.Run("flow has expired", func(t *testing.T) {
		store := createStore(t)
		expected := Flow{
			ID:     "flow-id",
			Expiry: time.Now().Add(-time.Hour),
		}

		err := store.Store(context.Background(), expected)
		assert.NoError(t, err)
		// We need a reference to resolve it
		err = store.StoreReference(context.Background(), expected.ID, refType, ref, futureExpiry())
		assert.NoError(t, err)

		actual, err := store.FindByReference(context.Background(), refType, ref)
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
}

func createStore(t *testing.T) Store {
	return NewStoabsStore(storage.CreateTestBBoltStore(t, path.Join(io.TestDirectory(t), "test.db")))
}

func Test_stoabsStore_pruneIfStale(t *testing.T) {

}

func futureExpiry() time.Time {
	// truncating makes assertion easier
	return time.Now().Add(time.Hour).Truncate(time.Second)
}
