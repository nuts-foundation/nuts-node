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
	bytes2 "bytes"
	"encoding/json"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
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
	assert.True(t, bytes2.Compare(transaction.Data(), event.Transaction.Data()) == 0)
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
}

func TestSubscriber_Save(t *testing.T) {
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

		_ = kvStore.Write(func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		kvStore.ReadShelf(s.shelfName(), func(reader stoabs.Reader) error {
			data, err := reader.Get(stoabs.BytesKey(event.Hash.Slice()))
			var e Event
			_ = json.Unmarshal(data, &e)

			assert.NoError(t, err)
			assert.Equal(t, 1, e.Retries)
			assert.Equal(t, event.Hash.String(), e.Hash.String())

			return nil
		})
	})

	t.Run("Not stored if no persistency", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
		s := NewNotifier(t.Name(), dummyFunc)

		err := kvStore.Write(func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})
		assert.NoError(t, err)

		kvStore.ReadShelf(s.(*notifier).shelfName(), func(reader stoabs.Reader) error {
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

		err := kvStore.Write(func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})
		assert.NoError(t, err)

		kvStore.ReadShelf(s.shelfName(), func(reader stoabs.Reader) error {
			data, err := reader.Get(stoabs.BytesKey(event.Hash.Slice()))

			assert.NoError(t, err)
			assert.Nil(t, data)

			return nil
		})
	})

	t.Run("Not overwritten", func(t *testing.T) {
		s, kvStore := persistentSubscriber(t)

		err := kvStore.Write(func(tx stoabs.WriteTx) error {
			_ = s.Save(tx, event)
			event.Retries = 2
			return s.Save(tx, event)
		})
		assert.NoError(t, err)

		kvStore.ReadShelf(s.shelfName(), func(reader stoabs.Reader) error {
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
		tx.EXPECT().GetShelfWriter(s.shelfName()).Return(writer, nil)
		writer.EXPECT().Get(stoabs.BytesKey(hash.EmptyHash().Slice())).Return(nil, errors.New("failure"))

		err := s.Save(tx, Event{Hash: hash.EmptyHash()})

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "failure")
	})
}

func TestSubscriber_Notify(t *testing.T) {
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

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			return counter.read() == 1, nil
		}, time.Second, "timeout while waiting for receiver")
		kvStore.ReadShelf(s.shelfName(), func(reader stoabs.Reader) error {
			e, err := s.readEvent(reader, hash.EmptyHash())

			assert.NoError(t, err)
			assert.Equal(t, 1, e.Retries)

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
		kvStore.WriteShelf(s.shelfName(), func(writer stoabs.Writer) error {
			return nil
		})
		s.Notify(event)

		time.Sleep(20 * time.Millisecond)

		assert.Equal(t, 0, counter.read())
	})
}

func TestSubscriber_Run(t *testing.T) {
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
	s := NewNotifier(t.Name(), counter.callbackFinished, WithPersistency(kvStore)).(*notifier)

	_ = kvStore.WriteShelf(s.shelfName(), func(writer stoabs.Writer) error {
		bytes, _ := json.Marshal(event)
		return writer.Put(stoabs.BytesKey(event.Hash.Slice()), bytes)
	})

	s.Run()

	test.WaitFor(t, func() (bool, error) {
		return counter.read() == 1, nil
	}, time.Second, "timeout while waiting for receiver")
}

func TestSubscriber_VariousFlows(t *testing.T) {
	transaction, _, _ := CreateTestTransaction(0)
	event := Event{Hash: hash.EmptyHash(), Transaction: transaction}
	t.Run("Happy flow", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		s := NewNotifier(t.Name(), counter.callback, WithPersistency(kvStore), WithRetryDelay(10*time.Millisecond)).(*notifier)
		defer s.Close()

		_ = kvStore.Write(func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			return counter.read() == 2, nil
		}, time.Second, "timeout while waiting for receiver")

		kvStore.ReadShelf(s.shelfName(), func(reader stoabs.Reader) error {
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

		_ = kvStore.Write(func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			var e *Event
			kvStore.ReadShelf(s.shelfName(), func(reader stoabs.Reader) error {
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
		event := Event{Hash: hash.EmptyHash(), Transaction: transaction, Retries: 95}
		s := NewNotifier(t.Name(), counter.callbackFailure, WithPersistency(kvStore), WithRetryDelay(time.Nanosecond)).(*notifier)
		defer s.Close()

		_ = kvStore.Write(func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			var e *Event
			kvStore.ReadShelf(s.shelfName(), func(reader stoabs.Reader) error {
				e, _ = s.readEvent(reader, hash.EmptyHash())
				return nil
			})

			return e.Retries == 100, nil
		}, time.Second, "timeout while waiting for receiver")

		events, err := s.GetFailedEvents()

		assert.NoError(t, err)
		assert.Len(t, events, 1)
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
	return false, errors.New("error")
}

func (cc *callbackCounter) read() int {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	return cc.count
}
