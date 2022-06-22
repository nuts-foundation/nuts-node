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
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/test"
	"go.uber.org/atomic"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

func TestState_relayingFuncs(t *testing.T) {
	println("start")
	ctx := context.Background()
	txState := createState(t)
	tx, _, _ := CreateTestTransaction(1)
	payload := []byte{0, 0, 0, 1}
	println("pre-add")
	txState.Add(ctx, tx, payload)
	println("post-add")
	payloadHash := hash.SHA256Sum(payload)
	lastTx := tx
	for i := 1; i < 10; i++ {
		lastTx, _, _ = CreateTestTransaction(uint32(i+1), lastTx)
		err := txState.Add(ctx, lastTx, []byte{0, 0, 0, byte(i + 1)})
		assert.NoError(t, err)
	}

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
		txs, err := txState.FindBetweenLC(0, 10)
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, txs, 10)
	})

	t.Run("ReadPayload", func(t *testing.T) {
		result, err := txState.ReadPayload(ctx, payloadHash)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, payload, result)
	})

	t.Run("State", func(t *testing.T) {
		heads := txState.Heads(ctx)

		assert.Len(t, heads, 1)
		assert.Equal(t, lastTx.Ref(), heads[0])
	})

	t.Run("Walk", func(t *testing.T) {
		var clock uint32
		err := txState.Walk(ctx, func(transaction Transaction) bool {
			clock++
			return transaction.Clock() == clock
		}, 0)
		assert.NoError(t, err)
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
	t.Run("all shelfs created", func(t *testing.T) {
		txState := createState(t)

		// createState already calls Start

		err := txState.(*state).db.Read(func(tx stoabs.ReadTx) error {
			for _, shelf := range []string{transactionsShelf, headsShelf, clockShelf, payloadsShelf, ibltShelf, xorShelf} {
				reader, _ := tx.GetShelfReader(shelf)
				assert.NotNil(t, reader)
			}
			return nil
		})
		assert.NoError(t, err)
	})
	t.Run("error - verifier failed", func(t *testing.T) {
		ctx := context.Background()
		txState := createState(t, func(_ stoabs.ReadTx, _ Transaction) error {
			return errors.New("failed")
		})
		tx := CreateTestTransactionWithJWK(0)
		err := txState.Add(ctx, tx, nil)
		println(2)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "transaction verification failed")
		present, err := txState.IsPresent(ctx, tx.Ref())
		assert.NoError(t, err)
		assert.False(t, present)
	})
}

func TestState_Notifier(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		s := createState(t).(*state)

		_, err := s.Notifier(t.Name(), dummyFunc)

		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, s.notifiers, 1)
	})

	t.Run("error on adding same notifier twice", func(t *testing.T) {
		s := createState(t)
		_, _ = s.Notifier(t.Name(), dummyFunc)

		_, err := s.Notifier(t.Name(), dummyFunc)

		assert.Error(t, err)
	})
}

func TestState_Observe(t *testing.T) {
	t.Run("transaction added", func(t *testing.T) {
		ctx := context.Background()
		txState := createState(t)
		var actual Transaction
		txState.RegisterTransactionObserver(func(_ stoabs.WriteTx, transaction Transaction) error {
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
		txState.RegisterTransactionObserver(func(_ stoabs.WriteTx, transaction Transaction) error {
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
		txState := createState(t, func(_ stoabs.ReadTx, tx Transaction) error {
			return errors.New("verification failed")
		})
		_ = txState.Start()

		err := txState.Add(ctx, transaction{}, nil)

		assert.Error(t, err)
	})

	t.Run("notifies receiver for transaction", func(t *testing.T) {
		ctx := context.Background()
		var received atomic.Bool
		s := createState(t)
		s.Notifier(t.Name(), func(event Event) (bool, error) {
			received.Toggle()
			return true, nil
		}, WithSelectionFilter(func(event Event) bool {
			return event.Type == TransactionEventType
		}))

		err := s.Add(ctx, transaction{}, nil)

		if !assert.NoError(t, err) {
			return
		}

		test.WaitFor(t, func() (bool, error) {
			return received.Load(), nil
		}, time.Second, "timeout while waiting for event")
	})

	t.Run("does not notify receiver for missing payload", func(t *testing.T) {
		ctx := context.Background()
		s := createState(t)
		s.Notifier(t.Name(), func(event Event) (bool, error) {
			t.Fail()
			return true, nil
		}, WithSelectionFilter(func(event Event) bool {
			return event.Type == PayloadEventType
		}), WithRetryDelay(time.Nanosecond))

		err := s.Add(ctx, transaction{}, nil)

		if !assert.NoError(t, err) {
			return
		}
		// this is enough to make it fail otherwise
		time.Sleep(10 * time.Millisecond)
	})

	t.Run("notifies receiver for payload", func(t *testing.T) {
		ctx := context.Background()
		var received atomic.Bool
		s := createState(t)
		s.Notifier(t.Name(), func(event Event) (bool, error) {
			received.Toggle()
			return true, nil
		}, WithSelectionFilter(func(event Event) bool {
			return event.Type == PayloadEventType
		}))
		tx, _, _ := CreateTestTransaction(0)
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, 0)

		err := s.Add(ctx, tx, payload)

		if !assert.NoError(t, err) {
			return
		}
		test.WaitFor(t, func() (bool, error) {
			return received.Load(), nil
		}, time.Second, "timeout while waiting for event")
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
	payload := []byte("payload")
	tx, _, _ := CreateTestTransactionEx(1, hash.SHA256Sum(payload), nil)
	dagClock := 3 * PageSize / 2
	tx.(*transaction).lamportClock = dagClock
	err := txState.Add(ctx, tx, payload)
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
	payload := []byte("payload")
	tx, _, _ := CreateTestTransactionEx(1, hash.SHA256Sum(payload), nil)
	dagClock := 3 * PageSize / 2
	tx.(*transaction).lamportClock = dagClock
	err := txState.Add(ctx, tx, payload)
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

func TestState_updateTrees(t *testing.T) {
	setup := func(t *testing.T) State {
		txState := createState(t)
		err := txState.Start()
		if !assert.NoError(t, err) {
			t.Fatal(err)
		}
		return txState
	}
	ctx := context.Background()

	t.Run("receiver for public transaction without payload", func(t *testing.T) {
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

func Test_createStore(t *testing.T) {
	assert.NotNil(t, createState(t))
}

func createState(t *testing.T, verifier ...Verifier) State {
	testDir := io.TestDirectory(t)
	//lvl, err := log.ParseLevel("trace")
	//if err != nil {
	//	panic("log level failed")
	//}
	//log.SetLevel(lvl)
	//log.SetFormatter(&log.TextFormatter{ForceColors: true})
	bboltStore, err := bbolt.CreateBBoltStore(filepath.Join(testDir, "test_state"), stoabs.WithNoSync())
	if err != nil {
		t.Fatal("failed to create store: ", err)
	}
	s, _ := NewState(bboltStore, verifier...)
	println("pre-start")
	s.Start()
	println("post-start")
	t.Cleanup(func() {
		s.Shutdown()
	})
	return s
}
