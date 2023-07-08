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

package dag

import (
	"context"
	"encoding/binary"
	"github.com/magiconair/properties/assert"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"path/filepath"
	"testing"
	"time"
)

func TestXorTreeRepair(t *testing.T) {
	t.Cleanup(func() {
		goleak.VerifyNone(t)
	})

	tx, _, _ := CreateTestTransaction(1)
	t.Run("xor tree repaired after 2 signals", func(t *testing.T) {
		txState := createXorTreeRepairState(t, tx)
		require.NoError(t, txState.Start())
		txState.xorTree = newTreeStore(xorShelf, tree.New(tree.NewXor(), PageSize))

		// twice to set circuit to red
		txState.IncorrectStateDetected()
		txState.IncorrectStateDetected()

		// await for XOR to change
		test.WaitFor(t, func() (bool, error) {
			txState.xorTreeRepair.mutex.Lock()
			defer txState.xorTreeRepair.mutex.Unlock()

			xorRoot := txState.xorTree.tree.Root()
			hashRoot := xorRoot.(*tree.Xor).Hash()
			return hashRoot.Equals(tx.Ref()), nil
		}, time.Second, "xorTree not updated within wait period")
	})
	t.Run("checkPage executed after 2 signals", func(t *testing.T) {
		txState := createXorTreeRepairState(t, tx)
		txState.xorTree = newTreeStore(xorShelf, tree.New(tree.NewXor(), PageSize))

		// twice to set circuit to red
		txState.IncorrectStateDetected()
		txState.IncorrectStateDetected()
		txState.xorTreeRepair.checkPage()

		assert.Equal(t, tx.Ref(), xorRootDate(txState))
	})
	t.Run("checkPage not executed after 1 signal", func(t *testing.T) {
		txState := createXorTreeRepairState(t, tx)
		txState.xorTree = newTreeStore(xorShelf, tree.New(tree.NewXor(), PageSize))

		// twice to set circuit to yellow
		txState.IncorrectStateDetected()
		txState.xorTreeRepair.checkPage()

		assert.Equal(t, hash.EmptyHash(), xorRootDate(txState))
	})
	t.Run("checkPage not executed after okState", func(t *testing.T) {
		txState := createXorTreeRepairState(t, tx)
		txState.xorTree = newTreeStore(xorShelf, tree.New(tree.NewXor(), PageSize))

		// twice to set circuit to red
		txState.IncorrectStateDetected()
		txState.IncorrectStateDetected()
		// back to green
		txState.CorrectStateDetected()
		txState.xorTreeRepair.checkPage()

		assert.Equal(t, hash.EmptyHash(), xorRootDate(txState))
	})
	t.Run("checkPage executed for multiple pages", func(t *testing.T) {
		txState := createXorTreeRepairState(t, tx)
		prev := tx
		expectedHash := tx.Ref()
		for i := uint32(1); i < 600; i++ {
			tx2, _, _ := CreateTestTransaction(i, prev)
			payload := make([]byte, 4)
			binary.BigEndian.PutUint32(payload, i)
			_ = txState.Add(context.Background(), tx2, payload)
			prev = tx2
			expectedHash = expectedHash.Xor(tx2.Ref())
		}
		require.NoError(t, txState.Start())
		txState.xorTree = newTreeStore(xorShelf, tree.New(tree.NewXor(), PageSize))

		// twice to set circuit to red
		txState.IncorrectStateDetected()
		txState.IncorrectStateDetected()

		// await for XOR to change
		test.WaitFor(t, func() (bool, error) {
			txState.xorTreeRepair.mutex.Lock()
			defer txState.xorTreeRepair.mutex.Unlock()

			xorRoot := txState.xorTree.tree.Root()
			hashRoot := xorRoot.(*tree.Xor).Hash()
			return hashRoot.Equals(expectedHash), nil
		}, 5*time.Second, "xorTree not updated within wait period")
	})
}

func xorRootDate(s *state) hash.SHA256Hash {
	return s.xorTree.tree.Root().(*tree.Xor).Hash()
}

func createXorTreeRepairState(t testing.TB, tx Transaction) *state {
	txState := createStoppedState(t)
	txState.xorTreeRepair.ticker = time.NewTicker(5 * time.Millisecond)
	payload := []byte{0, 0, 0, 1}
	txState.Add(context.Background(), tx, payload)
	return txState
}

func createStoppedState(t testing.TB) *state {
	testDir := io.TestDirectory(t)
	bboltStore, err := bbolt.CreateBBoltStore(filepath.Join(testDir, "test_state"), stoabs.WithNoSync())
	if err != nil {
		t.Fatal("failed to create store: ", err)
	}
	s, err := NewState(bboltStore)
	require.NoError(t, err)
	t.Cleanup(func() {
		s.Shutdown()
	})
	return s.(*state)
}
