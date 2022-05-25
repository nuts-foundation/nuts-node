/*
 * Nuts node
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
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/network/storage"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"go.etcd.io/bbolt"
)

func TestNewState(t *testing.T) {
	t.Run("error creating DB files", func(t *testing.T) {
		_, err := NewState("state_test.go")

		assert.EqualError(t, err, "unable to create BBolt database: mkdir state_test.go: not a directory")
	})
}

func TestState_relayingFuncs(t *testing.T) {
	ctx := context.Background()
	txState := createState(t)
	tx, _, _ := CreateTestTransaction(1)
	payload := []byte{0, 0, 0, 1}
	txState.Add(ctx, tx, payload)
	payloadHash := hash.SHA256Sum(payload)

	t.Run("GetTransaction", func(t *testing.T) {
		txResult, err := txState.GetTransaction(ctx, tx.Ref())

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, tx, txResult)
		assert.Equal(t, uint32(0), txResult.Clock())
	})

	t.Run("IsPayloadPresent", func(t *testing.T) {
		result, err := txState.IsPayloadPresent(ctx, payloadHash)

		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, result)
	})

	t.Run("IsPresent", func(t *testing.T) {
		result, err := txState.IsPresent(ctx, tx.Ref())

		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, result)
	})

	t.Run("FindBetweenLC", func(t *testing.T) {
		txs, err := txState.FindBetweenLC(0, 1)

		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, txs, 1)
	})

	t.Run("ReadPayload", func(t *testing.T) {
		result, err := txState.ReadPayload(ctx, payloadHash)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, payload, result)
	})
}

func TestState_Shutdown(t *testing.T) {
	txState := createState(t).(*state)

	err := txState.Shutdown()

	if !assert.NoError(t, err) {
		return
	}
}

func TestState_Start(t *testing.T) {
	t.Run("error - verifier failed", func(t *testing.T) {
		ctx := context.Background()
		txState := createState(t, func(_ *bbolt.Tx, _ Transaction) error {
			return errors.New("failed")
		})
		tx := CreateTestTransactionWithJWK(0)

		err := txState.Add(ctx, tx, nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "transaction verification failed")
		present, err := txState.IsPresent(ctx, tx.Ref())
		assert.NoError(t, err)
		assert.False(t, present)
	})
}

func TestState_Observe(t *testing.T) {
	t.Run("called with correct TX context", func(t *testing.T) {
		tests := []bool{true, false}
		for _, expected := range tests {
			t.Run(fmt.Sprintf("TX active: %v", expected), func(t *testing.T) {
				ctx := context.Background()
				txState := createState(t)
				var actual bool
				txState.RegisterTransactionObserver(func(ctx context.Context, transaction Transaction) error {
					_, actual = storage.BBoltTX(ctx)
					return nil
				}, expected)
				tx := CreateTestTransactionWithJWK(1)

				err := txState.Add(ctx, tx, nil)

				assert.NoError(t, err)
				assert.Equal(t, expected, actual)
			})
		}
	})
	t.Run("transaction added", func(t *testing.T) {
		ctx := context.Background()
		txState := createState(t)
		var actual Transaction
		txState.RegisterTransactionObserver(func(ctx context.Context, transaction Transaction) error {
			actual = transaction
			return nil
		}, false)
		expected := CreateTestTransactionWithJWK(1)

		err := txState.Add(ctx, expected, nil)

		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("transaction added with payload", func(t *testing.T) {
		ctx := context.Background()
		txState := createState(t)
		var actualTX Transaction
		var actualPayload []byte
		txState.RegisterTransactionObserver(func(ctx context.Context, transaction Transaction) error {
			actualTX = transaction
			return nil
		}, false)
		txState.RegisterPayloadObserver(func(transaction Transaction, payload []byte) error {
			actualPayload = payload
			return nil
		}, false)
		expected := CreateTestTransactionWithJWK(1)

		err := txState.Add(ctx, expected, []byte{0, 0, 0, 1})

		assert.NoError(t, err)
		assert.Equal(t, expected, actualTX)
		assert.Equal(t, []byte{0, 0, 0, 1}, actualPayload)
	})
	t.Run("transaction added with incorrect payload", func(t *testing.T) {
		ctx := context.Background()
		txState := createState(t)
		expected := CreateTestTransactionWithJWK(1)

		err := txState.Add(ctx, expected, []byte{1})

		assert.EqualError(t, err, "tx.PayloadHash does not match hash of payload")
	})
	t.Run("payload added", func(t *testing.T) {
		txState := createState(t)
		var actual []byte
		txState.RegisterPayloadObserver(func(tx Transaction, payload []byte) error {
			actual = payload
			return nil
		}, false)
		expected := []byte{1}

		err := txState.WritePayload(nil, hash.EmptyHash(), expected)

		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
}

func TestState_Add(t *testing.T) {
	t.Run("error for transaction verification failure", func(t *testing.T) {
		ctx := context.Background()
		txState := createState(t, func(_ *bbolt.Tx, tx Transaction) error {
			return errors.New("verification failed")
		})
		_ = txState.Start()

		err := txState.Add(ctx, transaction{}, nil)

		assert.Error(t, err)
	})
}

func TestState_Diagnostics(t *testing.T) {
	ctx := context.Background()
	txState := createState(t)
	payload := []byte("payload")
	doc1, _, _ := CreateTestTransactionEx(2, hash.SHA256Sum(payload), nil)
	err := txState.Add(ctx, doc1, payload)
	assert.NoError(t, err)
	diagnostics := txState.Diagnostics()
	assert.Len(t, diagnostics, 4)
	// Assert actual diagnostics
	lines := make([]string, 0)
	for _, diagnostic := range diagnostics {
		lines = append(lines, diagnostic.Name()+": "+diagnostic.String())
	}
	sort.Strings(lines)

	dbSize := txState.Statistics(context.Background())
	assert.NotZero(t, dbSize)

	actual := strings.Join(lines, "\n")
	expected := fmt.Sprintf(`dag_xor: %s
heads: [%s]
stored_database_size_bytes: %d
transaction_count: 1`, doc1.Ref(), doc1.Ref(), dbSize.DataSize)
	assert.Equal(t, expected, actual)
}

func TestState_XOR(t *testing.T) {
	// create state
	ctx := context.Background()
	txState := createState(t)
	err := txState.Start()
	if !assert.NoError(t, err) {
		return
	}
	payload := []byte("payload")
	tx, _, _ := CreateTestTransactionEx(1, hash.SHA256Sum(payload), nil)
	dagClock := 3 * PageSize / 2
	tx.(*transaction).lamportClock = dagClock
	err = txState.Add(ctx, tx, payload)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("requested clock larger than dag", func(t *testing.T) {
		xor, actualClock := txState.XOR(ctx, math.MaxUint32)

		assert.Equal(t, dagClock, actualClock)
		assert.Equal(t, tx.Ref(), xor)
	})
	t.Run("requested clock before last page", func(t *testing.T) {
		xor, actualClock := txState.XOR(ctx, uint32(1))

		assert.Equal(t, PageSize-1, actualClock)
		assert.Equal(t, hash.EmptyHash(), xor)
	})
	t.Run("requested clock on last page, lower than dag", func(t *testing.T) {
		xor, actualClock := txState.XOR(ctx, PageSize+1)

		assert.Equal(t, dagClock, actualClock)
		assert.Equal(t, tx.Ref(), xor)
	})
}

func TestState_IBLT(t *testing.T) {
	// create state
	ctx := context.Background()
	txState := createState(t)
	err := txState.Start()
	if !assert.NoError(t, err) {
		return
	}
	payload := []byte("payload")
	tx, _, _ := CreateTestTransactionEx(1, hash.SHA256Sum(payload), nil)
	dagClock := 3 * PageSize / 2
	tx.(*transaction).lamportClock = dagClock
	err = txState.Add(ctx, tx, payload)
	if !assert.NoError(t, err) {
		return
	}
	// expected iblt
	dagIBLT := tree.NewIblt(IbltNumBuckets)
	dagIBLT.Insert(tx.Ref())
	if !assert.False(t, dagIBLT.IsEmpty()) {
		return
	}

	t.Run("requested clock larger than dag", func(t *testing.T) {
		iblt, actualClock := txState.IBLT(ctx, math.MaxUint32)
		_ = iblt.Subtract(dagIBLT)

		assert.Equal(t, dagClock, actualClock)
		assert.True(t, iblt.IsEmpty(), iblt)
	})
	t.Run("requested clock before last page", func(t *testing.T) {
		iblt, actualClock := txState.IBLT(ctx, uint32(1))

		assert.Equal(t, PageSize-1, actualClock)
		assert.True(t, iblt.IsEmpty(), iblt)
	})
	t.Run("requested clock on last page, lower than dag", func(t *testing.T) {
		iblt, actualClock := txState.IBLT(ctx, PageSize+1)
		_ = iblt.Subtract(dagIBLT)

		assert.Equal(t, dagClock, actualClock)
		assert.True(t, iblt.IsEmpty(), iblt)
	})
}

func TestState_treeObserver(t *testing.T) {
	setup := func(t *testing.T) State {
		txState := createState(t)
		err := txState.Start()
		if !assert.NoError(t, err) {
			t.Fatal(err)
		}
		return txState
	}
	ctx := context.Background()

	t.Run("callback for public transaction without payload", func(t *testing.T) {
		txState := setup(t)
		tx := CreateTestTransactionWithJWK(1)

		err := txState.Add(ctx, tx, nil)

		if !assert.NoError(t, err) {
			return
		}

		xor, _ := txState.XOR(ctx, 1)
		assert.False(t, hash.EmptyHash().Equals(xor))
	})
}

func createState(t *testing.T, verifier ...Verifier) State {
	testDir := io.TestDirectory(t)
	s, _ := NewState(testDir, verifier...)
	t.Cleanup(func() {
		s.Shutdown()
	})
	return s
}
