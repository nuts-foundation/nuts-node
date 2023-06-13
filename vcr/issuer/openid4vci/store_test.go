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

package openid4vci

import (
	"context"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test"
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
	t.Run("automatic", func(t *testing.T) {
		store := createStore(t)
		// we call startPruning a second time ourselves, make sure not to leak the original goroutine
		cancelFunc := store.cancel
		defer cancelFunc()
		store.startPruning(10 * time.Millisecond)

		// Feed it something to prune
		expiredFlow := Flow{
			ID: "expired",
		}
		err := store.Store(ctx, expiredFlow)
		require.NoError(t, err)

		test.WaitFor(t, func() (bool, error) {
			var exists bool
			var err error
			return !exists, store.store.WriteShelf(ctx, flowsShelf, func(writer stoabs.Writer) error {
				exists, err = store.flowExists(writer, expiredFlow.ID)
				return err
			})
		}, time.Second, "time-out waiting for flow to be pruned")
	})
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

		flows, refs, err := store.prune(ctx, moment())

		assert.NoError(t, err)
		assert.Equal(t, 1, flows)
		assert.Equal(t, 0, refs)

		// Second round to assert there's nothing to prune now
		flows, refs, err = store.prune(ctx, moment())

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

		flows, refs, err := store.prune(ctx, moment())

		assert.NoError(t, err)
		assert.Equal(t, 0, flows)
		assert.Equal(t, 1, refs)

		// Second round to assert there's nothing to prune now
		flows, refs, err = store.prune(ctx, moment())

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

func moment() time.Time {
	return time.Now().In(time.UTC)
}

func pastExpiry() time.Time {
	return moment().Add(-time.Hour)
}

func futureExpiry() time.Time {
	// truncating makes assertion easier
	return moment().Add(time.Hour).Truncate(time.Second)
}
