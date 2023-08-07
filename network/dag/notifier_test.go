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
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"path"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestEvent_UnmarshalJSON(t *testing.T) {
	transaction, _, _ := CreateTestTransaction(0)
	payload := "payload"
	now := time.Now()
	event := Event{
		Type:        TransactionEventType,
		Hash:        transaction.Ref(),
		Retries:     1,
		Latest:      &now,
		Transaction: transaction,
		Payload:     []byte(payload),
	}

	bytes, _ := json.Marshal(event)
	err := json.Unmarshal(bytes, &event)

	require.NoError(t, err)

	assert.Equal(t, TransactionEventType, event.Type)
	assert.True(t, transaction.Ref().Equals(event.Hash))
	assert.Equal(t, 1, event.Retries)
	assert.True(t, now.Equal(*event.Latest))
	assert.Equal(t, payload, string(event.Payload))
	assert.Equal(t, transaction.Data(), event.Transaction.Data())
}

func TestNewNotifier(t *testing.T) {
	t.Run("sets default delay", func(t *testing.T) {
		s := NewNotifier(t.Name(), dummyFunc)

		assert.Equal(t, time.Second, s.(*notifier).retryDelay)
	})

	t.Run("sets delay with NotifierOption", func(t *testing.T) {
		s := NewNotifier(t.Name(), dummyFunc, WithRetryDelay(2*time.Second))

		assert.Equal(t, 2*time.Second, s.(*notifier).retryDelay)
	})

	t.Run("sets DB with NotifierOption", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		kvMock := stoabs.NewMockKVStore(ctrl)
		s := NewNotifier(t.Name(), dummyFunc, WithPersistency(kvMock))

		assert.True(t, s.(*notifier).isPersistent())
	})

	t.Run("sets filters with NotifierOption", func(t *testing.T) {
		s := NewNotifier(t.Name(), dummyFunc, WithSelectionFilter(func(event Event) bool {
			return true
		}))

		assert.Len(t, s.(*notifier).filters, 1)
	})

	t.Run("sets context based on parent context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		s := NewNotifier(t.Name(), dummyFunc, WithContext(ctx)).(*notifier)

		cancel()

		assert.NotNil(t, ctx, s.ctx.Err())
	})
}

func TestNotifier_Name(t *testing.T) {
	n := NewNotifier("test", dummyFunc)

	assert.Equal(t, "test", n.Name())
}

func TestNotifier_Save(t *testing.T) {
	ctx := context.Background()
	transaction, _, _ := CreateTestTransaction(0)
	payload := "payload"
	event := Event{
		Type:        TransactionEventType,
		Hash:        transaction.Ref(),
		Retries:     1,
		Transaction: transaction,
		Payload:     []byte(payload),
	}
	persistentSubscriber := func(t *testing.T, additionalOptions ...NotifierOption) (*notifier, stoabs.KVStore) {
		filePath := io.TestDirectory(t)
		kvStore := storage.CreateTestBBoltStore(t, path.Join(filePath, "test.db"))
		options := append(additionalOptions, WithPersistency(kvStore))
		s := NewNotifier(t.Name(), dummyFunc, options...)
		return s.(*notifier), kvStore
	}

	t.Run("OK", func(t *testing.T) {
		s, kvStore := persistentSubscriber(t)

		_ = kvStore.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		kvStore.ReadShelf(ctx, s.shelfName(), func(reader stoabs.Reader) error {
			data, err := reader.Get(stoabs.BytesKey(event.Hash.Slice()))
			var e Event
			_ = json.Unmarshal(data, &e)

			assert.NoError(t, err)
			assert.Equal(t, 1, e.Retries)
			assert.Equal(t, event.Hash.String(), e.Hash.String())
			assert.Nil(t, e.Latest)

			return nil
		})
	})

	t.Run("error on wrong DB", func(t *testing.T) {
		s, _ := persistentSubscriber(t)

		testDir := io.TestDirectory(t)
		dummyDB := storage.CreateTestBBoltStore(t, path.Join(testDir, "test.db"))

		err := dummyDB.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		assert.Error(t, err)
	})

	t.Run("Not stored if no persistency", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore := storage.CreateTestBBoltStore(t, path.Join(filePath, "test.db"))
		s := NewNotifier(t.Name(), dummyFunc)

		err := kvStore.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})
		assert.NoError(t, err)

		kvStore.ReadShelf(ctx, s.(*notifier).shelfName(), func(reader stoabs.Reader) error {
			data, err := reader.Get(stoabs.BytesKey(event.Hash.Slice()))

			assert.ErrorIs(t, err, stoabs.ErrKeyNotFound)
			assert.Nil(t, data)

			return nil
		})
	})

	t.Run("Not stored with exclusion filter", func(t *testing.T) {
		s, kvStore := persistentSubscriber(t, WithSelectionFilter(func(event Event) bool {
			return false
		}))

		err := kvStore.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})
		assert.NoError(t, err)

		kvStore.ReadShelf(ctx, s.shelfName(), func(reader stoabs.Reader) error {
			data, err := reader.Get(stoabs.BytesKey(event.Hash.Slice()))

			assert.ErrorIs(t, err, stoabs.ErrKeyNotFound)
			assert.Nil(t, data)

			return nil
		})
	})

	t.Run("Not overwritten", func(t *testing.T) {
		s, kvStore := persistentSubscriber(t)

		err := kvStore.Write(ctx, func(tx stoabs.WriteTx) error {
			_ = s.Save(tx, event)
			event.Retries = 2
			return s.Save(tx, event)
		})
		assert.NoError(t, err)

		kvStore.ReadShelf(ctx, s.shelfName(), func(reader stoabs.Reader) error {
			data, err := reader.Get(stoabs.BytesKey(event.Hash.Slice()))
			var e Event
			_ = json.Unmarshal(data, &e)

			assert.NoError(t, err)
			assert.Equal(t, 1, e.Retries)

			return nil
		})
	})

	t.Run("error on readEvent", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		kvMock := stoabs.NewMockKVStore(ctrl)
		tx := stoabs.NewMockWriteTx(ctrl)
		writer := stoabs.NewMockWriter(ctrl)
		s := NewNotifier(t.Name(), dummyFunc, WithPersistency(kvMock)).(*notifier)
		tx.EXPECT().Store().Return(kvMock)
		tx.EXPECT().GetShelfWriter(s.shelfName()).Return(writer)
		writer.EXPECT().Get(stoabs.BytesKey(hash.EmptyHash().Slice())).Return(nil, errors.New("failure"))

		err := s.Save(tx, Event{Hash: hash.EmptyHash()})

		assert.EqualError(t, err, "failure")
	})
}

func TestNotifier_Notify(t *testing.T) {
	ctx := context.Background()

	t.Run("ignored with inclusion filter", func(t *testing.T) {
		s := NewNotifier(t.Name(), func(event Event) (bool, error) {
			t.FailNow()
			return false, nil
		}, WithSelectionFilter(func(event Event) bool {
			return false
		}))

		s.Notify(Event{})
	})

	t.Run("OK - immediately", func(t *testing.T) {
		counter := callbackCounter{}
		s := NewNotifier(t.Name(), counter.callbackFinished)
		defer s.Close()

		s.Notify(Event{})

		test.WaitFor(t, func() (bool, error) {
			return counter.N.Load() == 1, nil
		}, time.Second, "timeout while waiting for receiver")

		assert.Equal(t, int64(1), counter.N.Load())
	})

	t.Run("OK - prometheus counters updated", func(t *testing.T) {
		counter := callbackCounter{}
		notifyCounter := &prometheusCounter{}
		finishedCounter := &prometheusCounter{}
		s := NewNotifier(t.Name(), counter.callbackFinished, withCounters(notifyCounter, finishedCounter))
		defer s.Close()

		s.Notify(Event{})

		test.WaitFor(t, func() (bool, error) {
			return counter.N.Load() == 1, nil
		}, time.Second, "timeout while waiting for receiver")

		assert.Equal(t, int64(1), notifyCounter.N.Load())
		assert.Equal(t, int64(1), finishedCounter.N.Load())
	})

	t.Run("OK - retried once", func(t *testing.T) {
		counter := callbackCounter{}
		s := NewNotifier(t.Name(), counter.callback, WithRetryDelay(10*time.Millisecond))
		defer s.Close()

		s.Notify(Event{})

		test.WaitFor(t, func() (bool, error) {
			return counter.N.Load() == 2, nil
		}, time.Second, "timeout while waiting for receiver")

		assert.Equal(t, int64(2), counter.N.Load())
	})

	t.Run("OK - updates DB", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		transaction, _, _ := CreateTestTransaction(0)
		kvStore := storage.CreateTestBBoltStore(t, path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		event := Event{Hash: hash.EmptyHash(), Transaction: transaction}
		now := time.Now()
		timeFunc = func() time.Time {
			return now
		}
		s := NewNotifier(t.Name(), counter.callback, WithPersistency(kvStore)).(*notifier)
		defer s.Close()
		kvStore.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			return counter.N.Load() == 1, nil
		}, time.Second, "timeout while waiting for receiver")
		kvStore.ReadShelf(ctx, s.shelfName(), func(reader stoabs.Reader) error {
			e, err := s.readEvent(reader, hash.EmptyHash())

			assert.NoError(t, err)
			require.NotNil(t, e)
			assert.Equal(t, 1, e.Retries)
			assert.True(t, now.Equal(*e.Latest))

			return nil
		})

		assert.Equal(t, int64(1), counter.N.Load())
	})

	t.Run("OK - stops when no longer available in DB", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		transaction, _, _ := CreateTestTransaction(0)
		kvStore := storage.CreateTestBBoltStore(t, path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		event := Event{Hash: hash.EmptyHash(), Transaction: transaction}
		s := NewNotifier(t.Name(), counter.callback, WithPersistency(kvStore), WithRetryDelay(time.Millisecond)).(*notifier)
		defer s.Close()

		// create bucket
		kvStore.WriteShelf(ctx, s.shelfName(), func(writer stoabs.Writer) error {
			return nil
		})
		s.Notify(event)

		time.Sleep(20 * time.Millisecond)

		assert.Equal(t, int64(0), counter.N.Load())
	})
}

func TestNotifier_Run(t *testing.T) {
	transaction, _, _ := CreateTestTransaction(0)
	payload := "payload"
	event := Event{
		Type:        TransactionEventType,
		Hash:        transaction.Ref(),
		Retries:     1,
		Transaction: transaction,
		Payload:     []byte(payload),
	}

	t.Run("OK - callback called", func(t *testing.T) {
		ctx := context.Background()
		filePath := io.TestDirectory(t)
		kvStore := storage.CreateTestBBoltStore(t, path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		s := NewNotifier(t.Name(), counter.callbackFinished, WithPersistency(kvStore), WithRetryDelay(time.Millisecond)).(*notifier)
		defer s.Close()

		_ = kvStore.WriteShelf(ctx, s.shelfName(), func(writer stoabs.Writer) error {
			bytes, _ := json.Marshal(event)
			return writer.Put(stoabs.BytesKey(event.Hash.Slice()), bytes)
		})

		err := s.Run()
		require.NoError(t, err)

		test.WaitFor(t, func() (bool, error) {
			return counter.N.Load() == 1, nil
		}, time.Second, "timeout while waiting for receiver")
	})

	t.Run("OK - callback errors", func(t *testing.T) {
		ctx := context.Background()
		filePath := io.TestDirectory(t)
		kvStore := storage.CreateTestBBoltStore(t, path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		counter.setCallbackError(errors.New("error"))
		s := NewNotifier(t.Name(), counter.callbackFailure, WithPersistency(kvStore), WithRetryDelay(time.Millisecond)).(*notifier)
		defer s.Close()

		_ = kvStore.WriteShelf(ctx, s.shelfName(), func(writer stoabs.Writer) error {
			bytes, _ := json.Marshal(event)
			return writer.Put(stoabs.BytesKey(event.Hash.Slice()), bytes)
		})

		// count the number of go routines
		goroutines := runtime.NumGoroutine()

		err := s.Run()
		require.NoError(t, err)

		test.WaitFor(t, func() (bool, error) {
			return counter.Err.Load() != nil, nil
		}, time.Second, "timeout while waiting for receiver")

		// the immediate callback has failed and the retry is scheduled within a new go routine
		assert.Equal(t, goroutines+1, runtime.NumGoroutine())
	})
}

func TestNotifier_VariousFlows(t *testing.T) {
	ctx := context.Background()
	transaction, _, _ := CreateTestTransaction(0)
	event := Event{Hash: hash.EmptyHash(), Transaction: transaction}
	t.Run("Happy flow", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore := storage.CreateTestBBoltStore(t, path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		s := NewNotifier(t.Name(), counter.callback, WithPersistency(kvStore), WithRetryDelay(10*time.Millisecond)).(*notifier)
		defer s.Close()

		_ = kvStore.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			return counter.N.Load() == 2, nil
		}, time.Second, "timeout while waiting for receiver")

		kvStore.ReadShelf(ctx, s.shelfName(), func(reader stoabs.Reader) error {
			e, err := s.readEvent(reader, hash.EmptyHash())

			assert.NoError(t, err)
			assert.Equal(t, 2, e.Retries)

			return nil
		})
	})

	t.Run("notifier marks event as finished", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore := storage.CreateTestBBoltStore(t, path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		s := NewNotifier(t.Name(), counter.callbackFinished, WithPersistency(kvStore), WithRetryDelay(10*time.Millisecond)).(*notifier)
		defer s.Close()

		_ = kvStore.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			var e *Event
			kvStore.ReadShelf(ctx, s.shelfName(), func(reader stoabs.Reader) error {
				e, _ = s.readEvent(reader, hash.EmptyHash())
				return nil
			})

			return e == nil, nil
		}, time.Second, "timeout while waiting for receiver")
	})

	t.Run("fails and stops at max attempts", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore := storage.CreateTestBBoltStore(t, path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		notifiedCounter := &prometheusCounter{}
		event := Event{Hash: hash.EmptyHash(), Transaction: transaction, Retries: 95}
		s := NewNotifier(t.Name(), counter.callbackFailure, WithPersistency(kvStore), WithRetryDelay(time.Nanosecond), withCounters(notifiedCounter, nil)).(*notifier)
		defer s.Close()

		_ = kvStore.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			var e *Event
			kvStore.ReadShelf(ctx, s.shelfName(), func(reader stoabs.Reader) error {
				e, _ = s.readEvent(reader, hash.EmptyHash())
				return nil
			})

			return e.Retries == 100, nil
		}, time.Second, "timeout while waiting for receiver")

		events, err := s.GetFailedEvents()

		assert.NoError(t, err)
		assert.Len(t, events, 1)
		assert.Equal(t, int64(5), counter.N.Load())
		assert.Equal(t, int64(5), notifiedCounter.N.Load())
		assert.Equal(t, "default callblackCounter test error", events[0].Error)
	})

	t.Run("fails on fatal event before scheduling retry ", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore := storage.CreateTestBBoltStore(t, path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		counter.setCallbackError(EventFatal{errors.New("fatal error")})
		s := NewNotifier(t.Name(), counter.callbackFailure, WithPersistency(kvStore), WithRetryDelay(time.Nanosecond)).(*notifier)
		defer s.Close()
		ctx := context.Background()

		_ = kvStore.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			var e *Event
			kvStore.ReadShelf(ctx, s.shelfName(), func(reader stoabs.Reader) error {
				e, _ = s.readEvent(reader, hash.EmptyHash())
				return nil
			})
			return e.Retries >= maxRetries, nil
		}, time.Second, "timeout while waiting for receiver")

		events, err := s.GetFailedEvents()

		assert.NoError(t, err)
		assert.Len(t, events, 1)
		assert.Equal(t, int64(1), counter.N.Load())
		assert.Equal(t, "fatal error", events[0].Error)
	})

	t.Run("fails on fatal event while retrying", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore := storage.CreateTestBBoltStore(t, path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		s := NewNotifier(t.Name(), counter.callbackFailure, WithPersistency(kvStore), WithRetryDelay(time.Millisecond)).(*notifier)
		defer s.Close()
		ctx := context.Background()

		_ = kvStore.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			var e *Event
			kvStore.ReadShelf(ctx, s.shelfName(), func(reader stoabs.Reader) error {
				e, _ = s.readEvent(reader, hash.EmptyHash())
				if e.Retries == 5 {
					counter.setCallbackError(EventFatal{errors.New("fatal error")})
				}
				return nil
			})
			return e.Retries >= maxRetries, nil
		}, time.Second, "timeout while waiting for receiver")

		events, err := s.GetFailedEvents()

		assert.NoError(t, err)
		assert.Len(t, events, 1)
		assert.Equal(t, int64(6), counter.N.Load())
		assert.Equal(t, "fatal error", events[0].Error)
	})

	t.Run("OK - incomplete event logs error", func(t *testing.T) {
		counter := callbackCounter{}
		kvStore := storage.CreateTestBBoltStore(t, path.Join(t.TempDir(), "test.db"))
		s := NewNotifier(t.Name(), counter.callback, WithRetryDelay(time.Millisecond), WithPersistency(kvStore)).(*notifier)
		defer s.Close()

		event := Event{Hash: hash.EmptyHash(), Transaction: transaction}
		event.Retries = retriesFailedThreshold // needed to appear in failed events
		_ = kvStore.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			var e *Event
			kvStore.ReadShelf(ctx, s.shelfName(), func(reader stoabs.Reader) error {
				e, _ = s.readEvent(reader, hash.EmptyHash())
				return nil
			})
			return e.Retries > retriesFailedThreshold, nil // +1 from starting condition
		}, time.Second, "timeout while waiting for receiver")

		events, err := s.GetFailedEvents()
		assert.NoError(t, err)
		require.Len(t, events, 1)
		assert.Equal(t, errEventIncomplete.Error(), events[0].Error)
	})
	t.Run("OK - completed event does not cause an error", func(t *testing.T) {
		kvStore := storage.CreateTestBBoltStore(t, path.Join(t.TempDir(), "test.db"))
		s := NewNotifier(t.Name(), nil, WithPersistency(kvStore)).(*notifier)

		// event is missing from kvStore, this should be interpreted as the event is completed
		err := s.notifyNow(event)

		assert.NoError(t, err)
	})
}

func dummyFunc(_ Event) (bool, error) {
	return true, nil
}

type callbackCounter struct {
	N   atomic.Int64
	Err atomic.Pointer[error]
}

func (c *callbackCounter) callback(_ Event) (bool, error) {
	c.N.Add(1)
	return false, nil
}

func (c *callbackCounter) callbackFinished(_ Event) (bool, error) {
	c.N.Add(1)
	return true, nil
}

func (cc *callbackCounter) callbackFailure(_ Event) (bool, error) {
	cc.N.Add(1)
	err := cc.Err.Load()
	if err != nil {
		return false, *err
	}
	return false, errors.New("default callblackCounter test error")
}

func (c *callbackCounter) setCallbackError(err error) {
	c.Err.Store(&err)
}

type prometheusCounter struct {
	N atomic.Int64
}

func (t *prometheusCounter) Desc() *prometheus.Desc {
	panic("implement me")
}

func (t *prometheusCounter) Write(metric *io_prometheus_client.Metric) error {
	panic("implement me")
}

func (t *prometheusCounter) Describe(descs chan<- *prometheus.Desc) {
	panic("implement me")
}

func (t *prometheusCounter) Collect(metrics chan<- prometheus.Metric) {
	panic("implement me")
}

func (t *prometheusCounter) Inc() {
	t.N.Add(1)
}

func (t *prometheusCounter) Add(f float64) {
	panic("implement me")
}
