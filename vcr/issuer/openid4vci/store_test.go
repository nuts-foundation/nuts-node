package openid4vci

import (
	"context"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		err = store.StoreReference(context.Background(), expected.ID, refType, ref, pastExpiry())
		assert.NoError(t, err)

		actual, err := store.FindByReference(context.Background(), refType, ref)
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
}

func Test_stoabsStore_Store(t *testing.T) {
	ctx := context.Background()
	t.Run("write, then read", func(t *testing.T) {
		store := createStore(t)
		expected := Flow{
			ID:     "flow-id",
			Expiry: futureExpiry(),
		}

		err := store.Store(ctx, expected)
		assert.NoError(t, err)
		// We need a reference to resolve it
		err = store.StoreReference(ctx, expected.ID, refType, ref, futureExpiry())
		assert.NoError(t, err)

		actual, err := store.FindByReference(ctx, refType, ref)
		assert.NoError(t, err)
		assert.Equal(t, expected, *actual)
	})
	t.Run("already exists", func(t *testing.T) {
		store := createStore(t)
		expected := Flow{
			ID:     "flow-id",
			Expiry: futureExpiry(),
		}

		err := store.Store(ctx, expected)
		assert.NoError(t, err)
		err = store.Store(ctx, expected)

		assert.EqualError(t, err, "OAuth2 flow with this ID already exists")
	})
	t.Run("flow has expired", func(t *testing.T) {
		store := createStore(t)
		expected := Flow{
			ID:     "flow-id",
			Expiry: pastExpiry(),
		}

		err := store.Store(ctx, expected)
		assert.NoError(t, err)
		// We need a reference to resolve it
		err = store.StoreReference(ctx, expected.ID, refType, ref, futureExpiry())
		assert.NoError(t, err)

		actual, err := store.FindByReference(ctx, refType, ref)
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
}

func Test_stoabsStore_prune(t *testing.T) {
	ctx := context.Background()
	t.Run("prunes expired flows", func(t *testing.T) {
		store := createStore(t)

		expiredFlow := Flow{
			ID: "expired",
		}
		unexpiredFlow := Flow{
			ID:     "unexpired",
			Expiry: futureExpiry(),
		}
		_ = store.Store(ctx, expiredFlow)
		_ = store.Store(ctx, unexpiredFlow)

		flows, refs, err := store.prune(ctx, time.Now())

		assert.NoError(t, err)
		assert.Equal(t, 1, flows)
		assert.Equal(t, 0, refs)

		// Second round to assert there's nothing to prune now
		flows, refs, err = store.prune(ctx, time.Now())

		assert.NoError(t, err)
		assert.Equal(t, 0, flows)
		assert.Equal(t, 0, refs)
	})
	t.Run("prunes expired refs", func(t *testing.T) {
		store := createStore(t)

		flow := Flow{
			ID:     "f",
			Expiry: futureExpiry(),
		}
		err := store.Store(ctx, flow)
		require.NoError(t, err)
		err = store.StoreReference(ctx, flow.ID, refType, "expired", pastExpiry())
		require.NoError(t, err)
		err = store.StoreReference(ctx, flow.ID, refType, "unexpired", futureExpiry())
		require.NoError(t, err)

		flows, refs, err := store.prune(ctx, time.Now())

		assert.NoError(t, err)
		assert.Equal(t, 0, flows)
		assert.Equal(t, 1, refs)

		// Second round to assert there's nothing to prune now
		flows, refs, err = store.prune(ctx, time.Now())

		assert.NoError(t, err)
		assert.Equal(t, 0, flows)
		assert.Equal(t, 0, refs)
	})
}

func createStore(t *testing.T) *stoabsStore {
	store := NewStoabsStore(storage.CreateTestBBoltStore(t, path.Join(io.TestDirectory(t), "test.db"))).(*stoabsStore)
	t.Cleanup(store.Close)
	return store
}

func pastExpiry() time.Time {
	return time.Now().Add(-time.Hour)
}

func futureExpiry() time.Time {
	// truncating makes assertion easier
	return time.Now().Add(time.Hour).Truncate(time.Second)
}
