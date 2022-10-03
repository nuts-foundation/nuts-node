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
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"path"
	"sync"
	"testing"
	"time"
)

func TestEvent_UnmarshalJSON(t *testing.T) {
	transaction, _, _ := CreateTestTransaction(0)
	payload := "payload"
	event := Event{
		Type:        TransactionEventType,
		Hash:        transaction.Ref(),
		Retries:     1,
		Transaction: transaction,
		Payload:     []byte(payload),
	}

	bytes, _ := json.Marshal(event)
	err := json.Unmarshal(bytes, &event)

	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, TransactionEventType, event.Type)
	assert.True(t, transaction.Ref().Equals(event.Hash))
	assert.Equal(t, 1, event.Retries)
	assert.Equal(t, payload, string(event.Payload))
	assert.Equal(t, transaction.Data(), event.Transaction.Data())
}

func TestNewSubscriber(t *testing.T) {
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
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
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

			return nil
		})
	})

	t.Run("error on wrong DB", func(t *testing.T) {
		s, _ := persistentSubscriber(t)

		testDir := io.TestDirectory(t)
		dummyDB, err := bbolt.CreateBBoltStore(path.Join(testDir, "test.db"))
		if err != nil {
			t.Fatal(err)
		}

		err = dummyDB.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		assert.Error(t, err)
	})

	t.Run("Not stored if no persistency", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
		s := NewNotifier(t.Name(), dummyFunc)

		err := kvStore.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})
		assert.NoError(t, err)

		kvStore.ReadShelf(ctx, s.(*notifier).shelfName(), func(reader stoabs.Reader) error {
			data, err := reader.Get(stoabs.BytesKey(event.Hash.Slice()))

			assert.NoError(t, err)
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

			assert.NoError(t, err)
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

	t.Run("error on ShelfWriter", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		kvMock := stoabs.NewMockKVStore(ctrl)
		tx := stoabs.NewMockWriteTx(ctrl)
		s := NewNotifier(t.Name(), dummyFunc, WithPersistency(kvMock)).(*notifier)
		tx.EXPECT().Store().Return(kvMock)
		tx.EXPECT().GetShelfWriter(s.shelfName()).Return(nil, errors.New("failure"))

		err := s.Save(tx, Event{})

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "failure")
	})

	t.Run("error on readEvent", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		kvMock := stoabs.NewMockKVStore(ctrl)
		tx := stoabs.NewMockWriteTx(ctrl)
		writer := stoabs.NewMockWriter(ctrl)
		s := NewNotifier(t.Name(), dummyFunc, WithPersistency(kvMock)).(*notifier)
		tx.EXPECT().Store().Return(kvMock)
		tx.EXPECT().GetShelfWriter(s.shelfName()).Return(writer, nil)
		writer.EXPECT().Get(stoabs.BytesKey(hash.EmptyHash().Slice())).Return(nil, errors.New("failure"))

		err := s.Save(tx, Event{Hash: hash.EmptyHash()})

		if !assert.Error(t, err) {
			return
		}
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
			return counter.read() == 1, nil
		}, time.Second, "timeout while waiting for receiver")

		assert.Equal(t, 1, counter.read())
	})

	t.Run("OK - prometheus counters updated", func(t *testing.T) {
		counter := callbackCounter{}
		notifyCounter := &prometheusCounter{}
		finishedCounter := &prometheusCounter{}
		s := NewNotifier(t.Name(), counter.callbackFinished, withCounters(notifyCounter, finishedCounter))
		defer s.Close()

		s.Notify(Event{})

		test.WaitFor(t, func() (bool, error) {
			return counter.read() == 1, nil
		}, time.Second, "timeout while waiting for receiver")

		assert.Equal(t, 1, notifyCounter.count)
		assert.Equal(t, 1, finishedCounter.count)
	})

	t.Run("OK - retried once", func(t *testing.T) {
		counter := callbackCounter{}
		s := NewNotifier(t.Name(), counter.callback, WithRetryDelay(10*time.Millisecond))
		defer s.Close()

		s.Notify(Event{})

		test.WaitFor(t, func() (bool, error) {
			return counter.read() == 2, nil
		}, time.Second, "timeout while waiting for receiver")

		assert.Equal(t, 2, counter.read())
	})

	t.Run("OK - updates DB", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		transaction, _, _ := CreateTestTransaction(0)
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		event := Event{Hash: hash.EmptyHash(), Transaction: transaction}
		s := NewNotifier(t.Name(), counter.callback, WithPersistency(kvStore)).(*notifier)
		defer s.Close()
		kvStore.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			return counter.read() == 1, nil
		}, time.Second, "timeout while waiting for receiver")
		kvStore.ReadShelf(ctx, s.shelfName(), func(reader stoabs.Reader) error {
			e, err := s.readEvent(reader, hash.EmptyHash())

			assert.NoError(t, err)
			if assert.NotNil(t, e) {
				assert.Equal(t, 1, e.Retries)
			}

			return nil
		})

		assert.Equal(t, 1, counter.read())
	})

	t.Run("OK - stops when no longer available in DB", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		transaction, _, _ := CreateTestTransaction(0)
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
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

		assert.Equal(t, 0, counter.read())
	})
}

func TestNotifier_Run(t *testing.T) {
	ctx := context.Background()
	filePath := io.TestDirectory(t)
	transaction, _, _ := CreateTestTransaction(0)
	kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
	counter := callbackCounter{}
	payload := "payload"
	event := Event{
		Type:        TransactionEventType,
		Hash:        transaction.Ref(),
		Retries:     1,
		Transaction: transaction,
		Payload:     []byte(payload),
	}
	s := NewNotifier(t.Name(), counter.callbackFinished, WithPersistency(kvStore), WithRetryDelay(time.Millisecond)).(*notifier)

	_ = kvStore.WriteShelf(ctx, s.shelfName(), func(writer stoabs.Writer) error {
		bytes, _ := json.Marshal(event)
		return writer.Put(stoabs.BytesKey(event.Hash.Slice()), bytes)
	})

	s.Run()

	test.WaitFor(t, func() (bool, error) {
		return counter.read() == 1, nil
	}, time.Second, "timeout while waiting for receiver")
}

func TestNotifier_VariousFlows(t *testing.T) {
	ctx := context.Background()
	transaction, _, _ := CreateTestTransaction(0)
	event := Event{Hash: hash.EmptyHash(), Transaction: transaction}
	t.Run("Happy flow", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		s := NewNotifier(t.Name(), counter.callback, WithPersistency(kvStore), WithRetryDelay(10*time.Millisecond)).(*notifier)
		defer s.Close()

		_ = kvStore.Write(ctx, func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			return counter.read() == 2, nil
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
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
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
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
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
		assert.Equal(t, 5, counter.read())
		assert.Equal(t, 5, notifiedCounter.count)
		assert.Equal(t, "error", events[0].Error)
	})

	t.Run("fails on fatal event before scheduling retry ", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		s := NewNotifier(t.Name(), counter.callbackFatalFailure, WithPersistency(kvStore), WithRetryDelay(time.Nanosecond)).(*notifier)
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
			return e.Retries == maxRetries+1, nil
		}, time.Second, "timeout while waiting for receiver")

		events, err := s.GetFailedEvents()

		assert.NoError(t, err)
		assert.Len(t, events, 1)
		assert.Equal(t, 1, counter.read())
		assert.Equal(t, "fatal error", events[0].Error)
	})

	t.Run("fails on fatal event while retrying", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
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
				return nil
			})
			if e.Retries == 5 {
				s.receiver = counter.callbackFatalFailure
			}
			return e.Retries == maxRetries+1, nil
		}, time.Second, "timeout while waiting for receiver")

		events, err := s.GetFailedEvents()

		assert.NoError(t, err)
		assert.Len(t, events, 1)
		assert.Equal(t, 6, counter.read())
		assert.Equal(t, "fatal error", events[0].Error)
	})
}

func dummyFunc(_ Event) (bool, error) {
	return true, nil
}

type callbackCounter struct {
	count int
	// mutex to prevent data race during test
	mutex sync.Mutex
}

func (cc *callbackCounter) callback(_ Event) (bool, error) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	cc.count++
	return false, nil
}

func (cc *callbackCounter) callbackFinished(_ Event) (bool, error) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	cc.count++
	return true, nil
}

func (cc *callbackCounter) callbackFailure(_ Event) (bool, error) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	cc.count++
	return false, errors.New("error")
}

func (cc *callbackCounter) callbackFatalFailure(_ Event) (bool, error) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	cc.count++
	return false, NewEventFatal(errors.New("fatal error"))
}

func (cc *callbackCounter) read() int {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	return cc.count
}

type prometheusCounter struct {
	count int
}

func (t prometheusCounter) Desc() *prometheus.Desc {
	panic("implement me")
}

func (t prometheusCounter) Write(metric *io_prometheus_client.Metric) error {
	panic("implement me")
}

func (t prometheusCounter) Describe(descs chan<- *prometheus.Desc) {
	panic("implement me")
}

func (t prometheusCounter) Collect(metrics chan<- prometheus.Metric) {
	panic("implement me")
}

func (t *prometheusCounter) Inc() {
	t.count++
}

func (t prometheusCounter) Add(f float64) {
	panic("implement me")
}
