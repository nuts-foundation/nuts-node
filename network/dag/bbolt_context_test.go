package dag

import (
	"context"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"go.etcd.io/bbolt"
	"os"
	"path"
	"testing"
)

func TestCallBBoltTXView(t *testing.T) {
	t.Run("assert TX is not writable", func(t *testing.T) {
		db, _ := bbolt.Open(path.Join(io.TestDirectory(t), "test.db"), os.ModePerm, nil)
		defer db.Close()

		err := bboltTXView(context.Background(), db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
			assert.False(t, tx.Writable())
			return nil
		})
		assert.NoError(t, err)
	})
}

func TestCallBBoltCallbackWithTX(t *testing.T) {
	db, _ := bbolt.Open(path.Join(io.TestDirectory(t), "test.db"), os.ModePerm, nil)
	defer db.Close()
	t.Run("read-only TX - no active TX", func(t *testing.T) {
		err := callBBoltCallbackWithTX(context.Background(), db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
			assert.False(t, tx.Writable())
			return nil
		}, false)
		assert.NoError(t, err)
	})
	t.Run("read-only TX - active TX", func(t *testing.T) {
		err := callBBoltCallbackWithTX(context.Background(), db, func(contextWithTX context.Context, outerTX *bbolt.Tx) error {
			return callBBoltCallbackWithTX(contextWithTX, db, func(contextWithTX context.Context, innerTX *bbolt.Tx) error {
				assert.Same(t, outerTX, innerTX)
				return nil
			}, false)
		}, false)
		assert.NoError(t, err)
	})
	t.Run("read-only TX - active (writable) TX", func(t *testing.T) {
		err := callBBoltCallbackWithTX(context.Background(), db, func(contextWithTX context.Context, outerTX *bbolt.Tx) error {
			return callBBoltCallbackWithTX(contextWithTX, db, func(contextWithTX context.Context, innerTX *bbolt.Tx) error {
				assert.Same(t, outerTX, innerTX)
				return nil
			}, false)
		}, true)
		assert.NoError(t, err)
	})
	t.Run("writable TX - no active TX", func(t *testing.T) {
		err := callBBoltCallbackWithTX(context.Background(), db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
			assert.True(t, tx.Writable())
			return nil
		}, true)
		assert.NoError(t, err)
	})
	t.Run("writable TX - active TX", func(t *testing.T) {
		err := callBBoltCallbackWithTX(context.Background(), db, func(contextWithTX context.Context, outerTX *bbolt.Tx) error {
			return callBBoltCallbackWithTX(contextWithTX, db, func(contextWithTX context.Context, innerTX *bbolt.Tx) error {
				assert.Same(t, outerTX, innerTX)
				return nil
			}, true)
		}, true)
		assert.NoError(t, err)
	})
	t.Run("error - writable TX - active TX is read-only", func(t *testing.T) {
		err := callBBoltCallbackWithTX(context.Background(), db, func(contextWithTX context.Context, outerTX *bbolt.Tx) error {
			return callBBoltCallbackWithTX(contextWithTX, db, func(contextWithTX context.Context, innerTX *bbolt.Tx) error {
				assert.Same(t, outerTX, innerTX)
				return nil
			}, true)
		}, false)
		assert.Error(t, err)
	})
}
