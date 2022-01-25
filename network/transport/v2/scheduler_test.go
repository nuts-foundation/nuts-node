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

package v2

import (
	"encoding/binary"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"go.etcd.io/bbolt"
)

var dummyCallback = func(_ hash.SHA256Hash) {}

func TestNewPayloadScheduler(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)

		opts := *bbolt.DefaultOptions
		opts.NoSync = true

		db, err := bbolt.Open(path.Join(testDir, "payload_test.db"), 0600, &opts)
		assert.NoError(t, err)

		t.Cleanup(func() {
			_ = db.Close()
		})

		scheduler, err := NewPayloadScheduler(db, 0, dummyCallback)

		assert.NoError(t, err)
		assert.NotNil(t, scheduler)
		assert.NotNil(t, scheduler.(*payloadScheduler).retryDelay)
		assert.NotNil(t, scheduler.(*payloadScheduler).callback)
	})
}

type callbackCounter struct {
	count int
	// mutex to prevent data race during test
	mutex sync.Mutex
}

func (cc *callbackCounter) callback(_ hash.SHA256Hash) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	cc.count++
}

func (cc *callbackCounter) read() int {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	return cc.count
}

func newTestPayloadScheduler(t *testing.T, callback jobCallBack) *payloadScheduler {
	testDir := io.TestDirectory(t)
	config := Config{Datadir: testDir}

	opts := *bbolt.DefaultOptions
	opts.NoSync = true

	db, err := bbolt.Open(path.Join(testDir, "payload_test.db"), 0600, &opts)
	assert.NoError(t, err)

	t.Cleanup(func() {
		_ = db.Close()
	})

	scheduler, err := NewPayloadScheduler(db, config.PayloadRetryDelay, callback)
	assert.NoError(t, err)

	scheduler.(*payloadScheduler).retryDelay = 10 * time.Second

	return scheduler.(*payloadScheduler)
}

func TestPayloadScheduler_Add(t *testing.T) {
	payloadRef := hash.SHA256Sum([]byte("test"))

	t.Run("ok", func(t *testing.T) {
		counter := callbackCounter{}
		scheduler := newTestPayloadScheduler(t, counter.callback)

		// also starts the go process
		err := scheduler.Schedule(payloadRef)

		if !assert.NoError(t, err) {
			return
		}

		test.WaitFor(t, func() (bool, error) {
			return counter.read() == 1, nil
		}, time.Second, "timeout while waiting for callback")

		dbPath := scheduler.db.Path()

		err = scheduler.Close()
		assert.NoError(t, err)

		assert.Equal(t, 1, counter.read())
		count := fromDB(t, dbPath, payloadRef)
		assert.Equal(t, uint16(1), count)
	})

	t.Run("ok - backoff ok", func(t *testing.T) {
		counter := callbackCounter{}

		scheduler := newTestPayloadScheduler(t, counter.callback)
		scheduler.retryDelay = 50 * time.Millisecond

		defer scheduler.Close()

		start := time.Now()
		err := scheduler.Schedule(payloadRef)

		if !assert.NoError(t, err) {
			return
		}

		test.WaitFor(t, func() (bool, error) {
			return counter.read() == 2, nil
		}, time.Second, "timeout while waiting for callback")

		// first try is immediate, second after 50 milliseconds
		assert.True(t, start.Add(50*time.Millisecond).Before(time.Now()))
	})
}

func TestPayloadScheduler_Start(t *testing.T) {
	payloadRef := hash.SHA256Sum([]byte("test"))

	t.Run("ok", func(t *testing.T) {
		counter := callbackCounter{}
		tenAsBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(tenAsBytes, 10)

		scheduler := newTestPayloadScheduler(t, counter.callback)

		addToDB(t, scheduler.db, payloadRef, tenAsBytes)

		err := scheduler.Run()
		if !assert.NoError(t, err) {
			return
		}

		test.WaitFor(t, func() (bool, error) {
			return counter.read() == 1, nil
		}, time.Second, "timeout while waiting for callback")

		dbPath := scheduler.db.Path()

		// to enable access to DB
		scheduler.Close()

		assert.Equal(t, 1, counter.read())
		count := fromDB(t, dbPath, payloadRef)
		assert.Equal(t, uint16(11), count)
	})
}

func TestPayloadScheduler_Remove(t *testing.T) {
	payloadRef := hash.SHA256Sum([]byte("test"))

	t.Run("ok - callback not called again", func(t *testing.T) {
		counter := callbackCounter{}

		scheduler := newTestPayloadScheduler(t, counter.callback)
		scheduler.retryDelay = 5 * time.Millisecond
		scheduler.callback = func(_ hash.SHA256Hash) {
			_ = scheduler.Finished(payloadRef)
			counter.callback(hash.SHA256Hash{})
		}

		defer scheduler.Close()

		_ = scheduler.Schedule(payloadRef)
		test.WaitFor(t, func() (bool, error) {
			return counter.read() == 1, nil
		}, time.Second, "timeout while waiting for callback")

		// allow enough time for callback to not be called
		time.Sleep(10 * time.Millisecond)

		assert.Equal(t, 1, counter.read())
	})
}

func addToDB(t *testing.T, db *bbolt.DB, hash hash.SHA256Hash, count []byte) {
	err := db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(payloadJobsBucketName)
		if err != nil {
			return err
		}
		return bucket.Put(hash.Slice(), count)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func fromDB(t *testing.T, filename string, hash hash.SHA256Hash) (count uint16) {
	db, err := bbolt.Open(filename, 0600, bbolt.DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(payloadJobsBucketName)
		if err != nil {
			return err
		}
		data := bucket.Get(hash.Slice())
		count = binary.LittleEndian.Uint16(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	return
}
