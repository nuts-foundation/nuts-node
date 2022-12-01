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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/test"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
)

func TestState_relayingFuncs(t *testing.T) {
	tx, _, _ := CreateTestTransaction(1)
	payload := []byte{0, 0, 0, 1}

	ctx := context.Background()
	txState := NewState()
	require.NoError(t, txState.Add(ctx, tx, payload))

	payloadHash := hash.SHA256Sum(payload)
	lastTx := tx
	for i := 1; i < 10; i++ {
		lastTx, _, _ = CreateTestTransaction(uint32(i+1), lastTx)
		require.NoError(t, txState.Add(ctx, lastTx, []byte{0, 0, 0, byte(i + 1)}))
	}

	t.Run("GetTransaction", func(t *testing.T) {
		txResult, err := txState.GetTransaction(ctx, tx.Ref())

		require.NoError(t, err)
		assert.Equal(t, tx, txResult)
		assert.Equal(t, uint32(0), txResult.Clock())
	})

	t.Run("IsPayloadPresent", func(t *testing.T) {
		result, err := txState.IsPayloadPresent(ctx, payloadHash)

		require.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("IsPresent", func(t *testing.T) {
		result, err := txState.IsPresent(ctx, tx.Ref())

		require.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("FindBetweenLC", func(t *testing.T) {
		txs, err := txState.FindBetweenLC(context.Background(), 0, 10)
		require.NoError(t, err)
		assert.Len(t, txs, 10)
	})

	t.Run("ReadPayload", func(t *testing.T) {
		result, err := txState.ReadPayload(ctx, payloadHash)

		require.NoError(t, err)
		assert.Equal(t, payload, result)
	})

	t.Run("Head", func(t *testing.T) {
		head, err := txState.Head(ctx)

		require.NoError(t, err)

		assert.Equal(t, lastTx.Ref(), head)
	})
}

func TestState_Shutdown(t *testing.T) {
	state := NewState()
	require.NoError(t, state.Shutdown())
}

func TestState_Notifier(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		s := NewState()
		_, err := s.Notifier(t.Name(), dummyFunc)
		require.NoError(t, err)
		assert.Len(t, s.Notifiers(), 1)
	})

	t.Run("error on adding same notifier twice", func(t *testing.T) {
		s := NewState()
		_, _ = s.Notifier(t.Name(), dummyFunc)
		_, err := s.Notifier(t.Name(), dummyFunc)
		assert.Error(t, err)
	})
}

func TestState_WritePayload(t *testing.T) {
	t.Run("notifies receiver for payload", func(t *testing.T) {
		txState := NewState()
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
		txState := NewState()
		txState.(*state).txVerifiers = append(txState.(*state).txVerifiers, func(tx Transaction) error {
			return errors.New("verification failed")
		})
		_ = txState.Start()

		assert.Error(t, txState.Add(ctx, transaction{}, nil))
	})

	t.Run("error when Notifier.Save fails", func(t *testing.T) {
		s := NewState()
		ctrl := gomock.NewController(t)
		subscriberMock := NewMockNotifier(ctrl)
		subscriberMock.EXPECT().Save(gomock.Any(), gomock.Any()).Return(errors.New("notifier test error"))
		s.(*state).notifiers.LoadOrStore(t.Name(), subscriberMock)

		assert.EqualError(t, s.Add(context.Background(), transaction{}, nil), "notifier test error")
	})

	t.Run("notifies receiver for transaction", func(t *testing.T) {
		s := NewState()
		ctx := context.Background()
		var received atomic.Bool
		s.Notifier(t.Name(), func(event Event) (bool, error) {
			received.Toggle()
			return true, nil
		}, WithSelectionFilter(func(event Event) bool {
			return event.Type == TransactionEventType
		}))

		require.NoError(t, s.Add(ctx, transaction{}, nil))

		test.WaitFor(t, func() (bool, error) {
			return received.Load(), nil
		}, time.Second, "timeout while waiting for event")
	})

	t.Run("does not notify receiver for missing payload", func(t *testing.T) {
		s := NewState()
		ctx := context.Background()
		s.Notifier(t.Name(), func(event Event) (bool, error) {
			t.Fail()
			return true, nil
		}, WithSelectionFilter(func(event Event) bool {
			return event.Type == PayloadEventType
		}), WithRetryDelay(time.Nanosecond))

		require.NoError(t, s.Add(ctx, transaction{}, nil))

		// this is enough to make it fail otherwise
		time.Sleep(10 * time.Millisecond)
	})

	t.Run("notifies receiver for payload", func(t *testing.T) {
		s := NewState()
		ctx := context.Background()
		var received atomic.Bool
		s.Notifier(t.Name(), func(event Event) (bool, error) {
			received.Toggle()
			return true, nil
		}, WithSelectionFilter(func(event Event) bool {
			return event.Type == PayloadEventType
		}))
		tx, _, _ := CreateTestTransaction(0)
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, 0)

		require.NoError(t, s.Add(ctx, tx, payload))

		test.WaitFor(t, func() (bool, error) {
			return received.Load(), nil
		}, time.Second, "timeout while waiting for event")
	})

	t.Run("transaction added with incorrect payload", func(t *testing.T) {
		txState := NewState()
		ctx := context.Background()
		expected := CreateTestTransactionWithJWK(1)

		err := txState.Add(ctx, expected, []byte{1})
		assert.EqualError(t, err, "tx.PayloadHash does not match hash of payload")
	})

	t.Run("afterCommit is not called for duplicate TX", func(t *testing.T) {
		s := NewState()
		ctx := context.Background()
		tx := CreateTestTransactionWithJWK(1)

		require.NoError(t, s.Add(ctx, tx, nil))
		assertCountMetric(t, s, 1)

		// check for Notifier not being called
		s.Notifier(t.Name(), func(event Event) (bool, error) {
			t.Fail()
			return true, nil
		}, WithSelectionFilter(func(event Event) bool {
			return event.Type == TransactionEventType
		}))

		// add again
		require.NoError(t, s.Add(ctx, tx, nil))
		time.Sleep(100 * time.Millisecond) // checking nothing happened is hard
		assertCountMetric(t, s, 1)
	})
}

func TestState_Diagnostics(t *testing.T) {
	txState := NewState()
	ctx := context.Background()
	payload := []byte("payload")
	doc1, _, _ := CreateTestTransactionEx(2, hash.SHA256Sum(payload), nil)
	require.NoError(t, txState.Add(ctx, doc1, payload))
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
	t.Skip("TODO(pascaldekloe): Not sure what the XOR test tries to do. It inserts a transaction with a clock gap. Are we supposed to support this, or is that more of a bug in the test? @gerard")

	txState := NewState()
	// create state
	ctx := context.Background()
	payload := []byte("payload")
	tx, _, _ := CreateTestTransactionEx(1, hash.SHA256Sum(payload), nil)
	dagClock := 3 * PageSize / 2
	tx.(*transaction).lamportClock = dagClock
	require.NoError(t, txState.Add(ctx, tx, payload))

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
	t.Skip("TODO(pascaldekloe): Not sure what the IBLT test tries to do. It inserts a transaction with a clock gap. Are we supposed to support this, or is that more of a bug in the test? @gerard")

	txState := NewState()
	ctx := context.Background()
	payload := []byte("payload")
	tx, _, _ := CreateTestTransactionEx(1, hash.SHA256Sum(payload), nil)
	dagClock := 3 * PageSize / 2
	tx.(*transaction).lamportClock = dagClock
	require.NoError(t, txState.Add(ctx, tx, payload))
	// expected iblt
	dagIBLT := tree.NewIblt(IbltNumBuckets)
	dagIBLT.Insert(tx.Ref())
	require.False(t, dagIBLT.Empty())

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
	txState := NewState()
	ctx := context.Background()
	payload := []byte("payload")
	tx, _, _ := CreateTestTransactionEx(1, hash.SHA256Sum(payload), nil)
	require.NoError(t, txState.Add(ctx, tx, payload))

	t.Run("count == 1", func(t *testing.T) {
		assertCountMetric(t, txState, 1)
	})

	t.Run("count survives restart", func(t *testing.T) {
		txState.Shutdown()
		txState.(*state).transactionCount = transactionCountCollector()
		txState.Start()

		assertCountMetric(t, txState, 1)
	})
}

func TestState_updateState(t *testing.T) {
	setup := func(t *testing.T) State {
		txState := NewState()
		require.NoError(t, txState.Start())
		return txState
	}
	ctx := context.Background()

	t.Run("receiver for public transaction without payload", func(t *testing.T) {
		txState := setup(t)
		tx := CreateTestTransactionWithJWK(1)

		err := txState.Add(ctx, tx, nil)

		require.NoError(t, err)

		xor, _ := txState.XOR(1)
		assert.False(t, hash.EmptyHash().Equals(xor))
	})
}

func assertCountMetric(t testing.TB, x State, count float64) {
	metric := &io_prometheus_client.Metric{}
	x.(*state).transactionCount.Write(metric)
	assert.Equal(t, count, *metric.Counter.Value)
}
