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
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/test"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"go.uber.org/atomic"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

func TestState_relayingFuncs(t *testing.T) {
	ctx := context.Background()
	txState := createState(t)
	tx, _, _ := CreateTestTransaction(1)
	payload := []byte{0, 0, 0, 1}
	txState.Add(ctx, tx, payload)
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
		txs, err := txState.FindBetweenLC(context.Background(), 0, 10)
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

	t.Run("Head", func(t *testing.T) {
		head, err := txState.Head(ctx)

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, lastTx.Ref(), head)
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

		err := txState.(*state).db.Read(context.Background(), func(tx stoabs.ReadTx) error {
			for _, shelf := range []string{transactionsShelf, headsShelf, clockShelf, payloadsShelf, ibltShelf, xorShelf} {
				reader := tx.GetShelfReader(shelf)
				assert.NotNil(t, reader)
			}
			return nil
		})
		assert.NoError(t, err)
	})
}

func TestState_Notifier(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		s := createState(t).(*state)

		_, err := s.Notifier(t.Name(), dummyFunc)

		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, s.Notifiers(), 1)
	})

	t.Run("error on adding same notifier twice", func(t *testing.T) {
		s := createState(t)
		_, _ = s.Notifier(t.Name(), dummyFunc)

		_, err := s.Notifier(t.Name(), dummyFunc)

		assert.Error(t, err)
	})
}

func TestState_Notifiers(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		s := createState(t).(*state)
		_, _ = s.Notifier(t.Name(), dummyFunc)

		notifiers := s.Notifiers()

		assert.Len(t, notifiers, 1)
	})
}

func TestState_WritePayload(t *testing.T) {
	t.Run("notifies receiver for payload", func(t *testing.T) {
		txState := createState(t)
		var received atomic.Bool
		_, _ = txState.Notifier(t.Name(), func(event Event) (bool, error) {
			received.Toggle()
			return true, nil
		}, WithSelectionFilter(func(event Event) bool {
			return event.Type == PayloadEventType
		}))
		expected := []byte{1}

		err := txState.WritePayload(context.Background(), transaction{}, hash.EmptyHash(), expected)

		assert.NoError(t, err)
		assert.True(t, received.Load())
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

	t.Run("transaction added with incorrect payload", func(t *testing.T) {
		ctx := context.Background()
		txState := createState(t)
		expected := CreateTestTransactionWithJWK(1)

		err := txState.Add(ctx, expected, []byte{1})

		assert.EqualError(t, err, "tx.PayloadHash does not match hash of payload")
	})

	t.Run("afterCommit is not called for duplicate TX", func(t *testing.T) {
		ctx := context.Background()
		s := createState(t).(*state)
		tx := CreateTestTransactionWithJWK(1)

		err := s.Add(ctx, tx, nil)
		if !assert.NoError(t, err) {
			return
		}
		assertCountMetric(t, s, 1)

		// check for Notifier not being called
		s.Notifier(t.Name(), func(event Event) (bool, error) {
			t.Fail()
			return true, nil
		}, WithSelectionFilter(func(event Event) bool {
			return event.Type == TransactionEventType
		}))

		// add again
		err = s.Add(ctx, tx, nil)
		if !assert.NoError(t, err) {
			return
		}
		time.Sleep(100 * time.Millisecond) // checking nothing happened is hard
		assertCountMetric(t, s, 1)
	})
}

func TestState_Diagnostics(t *testing.T) {
	ctx := context.Background()
	txState := createState(t).(*state)
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
	actual := strings.Join(lines, "\n")

	assert.Contains(t, actual, fmt.Sprintf("dag_xor: %s", doc1.Ref()))
	assert.Contains(t, actual, "transaction_count: 1")
	assert.Contains(t, actual, "failed_events: 0")
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
		xor, actualClock := txState.XOR(MaxLamportClock)

		assert.Equal(t, dagClock, actualClock)
		assert.Equal(t, tx.Ref(), xor)
	})
	t.Run("requested clock before last page", func(t *testing.T) {
		xor, actualClock := txState.XOR(uint32(1))

		assert.Equal(t, PageSize-1, actualClock)
		assert.Equal(t, hash.EmptyHash(), xor)
	})
	t.Run("requested clock on last page, lower than dag", func(t *testing.T) {
		xor, actualClock := txState.XOR(PageSize + 1)

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
	if !assert.False(t, dagIBLT.Empty()) {
		return
	}

	t.Run("requested clock larger than dag", func(t *testing.T) {
		iblt, actualClock := txState.IBLT(MaxLamportClock)
		_ = iblt.Subtract(dagIBLT)

		assert.Equal(t, dagClock, actualClock)
		assert.True(t, iblt.Empty(), iblt)
	})
	t.Run("requested clock before last page", func(t *testing.T) {
		iblt, actualClock := txState.IBLT(uint32(1))

		assert.Equal(t, PageSize-1, actualClock)
		assert.True(t, iblt.Empty(), iblt)
	})
	t.Run("requested clock on last page, lower than dag", func(t *testing.T) {
		iblt, actualClock := txState.IBLT(PageSize + 1)
		_ = iblt.Subtract(dagIBLT)

		assert.Equal(t, dagClock, actualClock)
		assert.True(t, iblt.Empty(), iblt)
	})
}

func TestState_InitialTransactionCountMetric(t *testing.T) {
	// create state
	ctx := context.Background()
	txState := createState(t).(*state)
	payload := []byte("payload")
	tx, _, _ := CreateTestTransactionEx(1, hash.SHA256Sum(payload), nil)
	err := txState.Add(ctx, tx, payload)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("count == 1", func(t *testing.T) {
		assertCountMetric(t, txState, 1)
	})

	t.Run("count survives restart", func(t *testing.T) {
		txState.Shutdown()
		txState.transactionCount = transactionCountCollector()
		txState.Start()

		assertCountMetric(t, txState, 1)
	})
}

func TestState_updateState(t *testing.T) {
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

		xor, _ := txState.XOR(1)
		assert.False(t, hash.EmptyHash().Equals(xor))
	})
}

func Test_createStore(t *testing.T) {
	assert.NotNil(t, createState(t))
}

func createState(t testing.TB, verifier ...Verifier) State {
	testDir := io.TestDirectory(t)
	bboltStore, err := bbolt.CreateBBoltStore(filepath.Join(testDir, "test_state"), stoabs.WithNoSync())
	if err != nil {
		t.Fatal("failed to create store: ", err)
	}
	s, err := NewState(bboltStore, verifier...)
	if err != nil {
		t.Fatal("failed to create store: ", err)
	}
	err = s.Start()
	if err != nil {
		t.Fatal("failed to start store: ", err)
	}
	t.Cleanup(func() {
		s.Shutdown()
	})
	return s
}

func assertCountMetric(t testing.TB, state *state, count float64) {
	metric := &io_prometheus_client.Metric{}
	state.transactionCount.Write(metric)
	assert.Equal(t, count, *metric.Counter.Value)
}

func BenchmarkState_loadTrees(b *testing.B) {
	state := createState(b).(*state)
	ctx := context.Background()

	// add a bunch of transactions
	maxDepth := 16
	nextLeaf := uint32(0)
	var current Transaction
	next, _, _ := CreateTestTransaction(0)
	for depth := 0; depth < maxDepth; depth++ {
		numLeaves := uint32(math.Pow(2, float64(depth)))
		for l := nextLeaf; l < numLeaves; l++ {
			current = next
			current.(*transaction).lamportClock = l * PageSize
			_ = state.Add(ctx, current, nil)
			next, _, _ = CreateTestTransaction(l, current)
			nextLeaf++
		}

		// benchmark reload state
		b.Run(fmt.Sprintf("Depth=%d Transactions=%d", depth, current.(*transaction).lamportClock+PageSize), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				state.loadState(ctx)
			}
		})
	}
}
