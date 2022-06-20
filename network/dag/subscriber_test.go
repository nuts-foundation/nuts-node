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
		Count:       1,
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
	assert.Equal(t, 1, event.Count)
	assert.Equal(t, payload, string(event.Payload))
	assert.True(t, bytes2.Compare(transaction.Data(), event.Transaction.Data()) == 0)
}

func TestNewSubscriber(t *testing.T) {
	t.Run("sets default delay", func(t *testing.T) {
		s := NewSubscriber(t.Name(), dummyFunc)

		assert.Equal(t, time.Second, s.(*subscriber).retryDelay)
	})

	t.Run("sets delay with SubscriberOption", func(t *testing.T) {
		s := NewSubscriber(t.Name(), dummyFunc, WithRetryDelay(2*time.Second))

		assert.Equal(t, 2*time.Second, s.(*subscriber).retryDelay)
	})

	t.Run("sets DB with SubscriberOption", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		kvMock := stoabs.NewMockKVStore(ctrl)
		s := NewSubscriber(t.Name(), dummyFunc, WithPersistency(kvMock))

		assert.True(t, s.(*subscriber).isPersistent())
	})

	t.Run("sets filters with SubscriberOption", func(t *testing.T) {
		s := NewSubscriber(t.Name(), dummyFunc, WithSelectionFilter(func(event Event) bool {
			return true
		}))

		assert.Len(t, s.(*subscriber).filters, 1)
	})
}

func TestSubscriber_Save(t *testing.T) {
	transaction, _, _ := CreateTestTransaction(0)
	payload := "payload"
	event := Event{
		Type:        TransactionEventType,
		Hash:        transaction.Ref(),
		Count:       1,
		Transaction: transaction,
		Payload:     []byte(payload),
	}
	persistentSubscriber := func(t *testing.T, additionalOptions ...SubscriberOption) (*subscriber, stoabs.KVStore) {
		filePath := io.TestDirectory(t)
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
		options := append(additionalOptions, WithPersistency(kvStore))
		s := NewSubscriber(t.Name(), dummyFunc, options...)
		return s.(*subscriber), kvStore
	}

	t.Run("OK", func(t *testing.T) {
		s, kvStore := persistentSubscriber(t)

		_ = kvStore.Write(func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		kvStore.ReadShelf(s.bucketName(), func(reader stoabs.Reader) error {
			data, err := reader.Get(stoabs.BytesKey(event.Hash.Slice()))
			var e Event
			_ = json.Unmarshal(data, &e)

			assert.NoError(t, err)
			assert.Equal(t, 1, e.Count)
			assert.Equal(t, event.Hash.String(), e.Hash.String())

			return nil
		})
	})

	t.Run("Not stored if no persistency", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
		s := NewSubscriber(t.Name(), dummyFunc)

		err := kvStore.Write(func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})
		assert.NoError(t, err)

		kvStore.ReadShelf(s.(*subscriber).bucketName(), func(reader stoabs.Reader) error {
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

		kvStore.ReadShelf(s.bucketName(), func(reader stoabs.Reader) error {
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
			event.Count = 2
			return s.Save(tx, event)
		})
		assert.NoError(t, err)

		kvStore.ReadShelf(s.bucketName(), func(reader stoabs.Reader) error {
			data, err := reader.Get(stoabs.BytesKey(event.Hash.Slice()))
			var e Event
			_ = json.Unmarshal(data, &e)

			assert.NoError(t, err)
			assert.Equal(t, 1, e.Count)

			return nil
		})
	})
}

func TestSubscriber_Notify(t *testing.T) {
	t.Run("ignored with inclusion filter", func(t *testing.T) {
		s := NewSubscriber(t.Name(), func(event Event) (bool, error) {
			t.FailNow()
			return false, nil
		}, WithSelectionFilter(func(event Event) bool {
			return false
		}))

		s.Notify(Event{})
	})

	t.Run("OK - immediately", func(t *testing.T) {
		counter := callbackCounter{}
		s := NewSubscriber(t.Name(), counter.callbackFinished)
		defer s.Close()

		s.Notify(Event{})

		test.WaitFor(t, func() (bool, error) {
			return counter.read() == 1, nil
		}, time.Second, "timeout while waiting for callback")

		assert.Equal(t, 1, counter.read())
	})

	t.Run("OK - retried once", func(t *testing.T) {
		counter := callbackCounter{}
		s := NewSubscriber(t.Name(), counter.callback, WithRetryDelay(10*time.Millisecond))
		defer s.Close()

		s.Notify(Event{})

		test.WaitFor(t, func() (bool, error) {
			return counter.read() == 2, nil
		}, time.Second, "timeout while waiting for callback")

		assert.Equal(t, 2, counter.read())
	})

	t.Run("OK - updates DB", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		transaction, _, _ := CreateTestTransaction(0)
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		event := Event{Hash: hash.EmptyHash(), Transaction: transaction}
		s := NewSubscriber(t.Name(), counter.callback, WithPersistency(kvStore)).(*subscriber)
		defer s.Close()

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			return counter.read() == 1, nil
		}, time.Second, "timeout while waiting for callback")
		kvStore.ReadShelf(s.bucketName(), func(reader stoabs.Reader) error {
			e, err := s.readEvent(reader, hash.EmptyHash())

			assert.NoError(t, err)
			assert.Equal(t, 1, e.Count)

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
		s := NewSubscriber(t.Name(), counter.callback, WithPersistency(kvStore), WithRetryDelay(time.Millisecond)).(*subscriber)
		defer s.Close()

		// create bucket
		kvStore.WriteShelf(s.bucketName(), func(writer stoabs.Writer) error {
			return nil
		})
		s.Notify(event)

		time.Sleep(20 * time.Millisecond)

		assert.Equal(t, 0, counter.read())
	})
}

func TestSubscriber_VariousFlows(t *testing.T) {
	transaction, _, _ := CreateTestTransaction(0)
	event := Event{Hash: hash.EmptyHash(), Transaction: transaction}
	t.Run("Happy flow", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		s := NewSubscriber(t.Name(), counter.callbackFinished, WithPersistency(kvStore), WithRetryDelay(10*time.Millisecond)).(*subscriber)
		defer s.Close()

		_ = kvStore.Write(func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			return counter.read() == 2, nil
		}, time.Second, "timeout while waiting for callback")

		kvStore.ReadShelf(s.bucketName(), func(reader stoabs.Reader) error {
			e, err := s.readEvent(reader, hash.EmptyHash())

			assert.NoError(t, err)
			assert.Equal(t, 2, e.Count)

			return nil
		})
	})

	t.Run("subscriber marks event as finished", func(t *testing.T) {
		filePath := io.TestDirectory(t)
		kvStore, _ := bbolt.CreateBBoltStore(path.Join(filePath, "test.db"))
		counter := callbackCounter{}
		s := NewSubscriber(t.Name(), counter.callbackFinished, WithPersistency(kvStore), WithRetryDelay(10*time.Millisecond)).(*subscriber)
		defer s.Close()

		_ = kvStore.Write(func(tx stoabs.WriteTx) error {
			return s.Save(tx, event)
		})

		s.Notify(event)

		test.WaitFor(t, func() (bool, error) {
			var e *Event
			kvStore.ReadShelf(s.bucketName(), func(reader stoabs.Reader) error {
				e, _ = s.readEvent(reader, hash.EmptyHash())
				return nil
			})

			return e == nil, nil
		}, time.Second, "timeout while waiting for callback")
	})
}

func dummyFunc(event Event) (bool, error) {
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

func (cc *callbackCounter) read() int {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	return cc.count
}
