/*
 * Copyright (C) 2022 Nuts community
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
