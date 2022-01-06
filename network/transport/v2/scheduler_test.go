/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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
	"os"
	"path"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"go.etcd.io/bbolt"
)

var dummyCallback = func(_ hash.SHA256Hash) {}

func TestNewPayloadScheduler(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		scheduler := NewPayloadScheduler("", 0, dummyCallback)

		assert.NotNil(t, scheduler)
		assert.NotNil(t, scheduler.(*payloadScheduler).dataDir)
		assert.NotNil(t, scheduler.(*payloadScheduler).retryDelay)
		assert.NotNil(t, scheduler.(*payloadScheduler).callback)
	})
}

func TestPayloadScheduler_Configure(t *testing.T) {
	t.Run("ok - default delay", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		config := Config{Datadir: testDir}
		scheduler := NewPayloadScheduler(config.Datadir, config.PayloadRetryDelay, dummyCallback)

		err := scheduler.Configure()

		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, scheduler)
		assert.Equal(t, 5*time.Second, scheduler.(*payloadScheduler).retryDelay)
	})

	t.Run("error - invalid DB location", func(t *testing.T) {
		config := Config{Datadir: "scheduler_test.go"}
		scheduler := NewPayloadScheduler(config.Datadir, config.PayloadRetryDelay, dummyCallback)

		err := scheduler.Configure()

		assert.EqualError(t, err, "unable to setup database: mkdir scheduler_test.go: not a directory")
	})
}

type callbackCounter struct {
	count int
	wg    sync.WaitGroup
	// mutex to prevent data race during test
	mutex sync.Mutex
}

func (cc *callbackCounter) wait(count int) {
	cc.mutex.Lock()

	if cc.count >= count {
		return
	}

	cc.mutex.Unlock()
	cc.wg.Add(count)
	cc.wg.Wait()
}

func (cc *callbackCounter) callback(_ hash.SHA256Hash) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	cc.count++
	cc.wg.Done()
}

func TestPayloadScheduler_Add(t *testing.T) {
	payloadRef := hash.SHA256Sum([]byte("test"))

	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		config := Config{Datadir: testDir}
		counter := callbackCounter{}
		scheduler := NewPayloadScheduler(config.Datadir, config.PayloadRetryDelay, counter.callback)
		_ = scheduler.Configure()

		// also starts the go process
		err := scheduler.Schedule(payloadRef)

		if !assert.NoError(t, err) {
			return
		}

		counter.wait(1)

		// to enable access to DB
		scheduler.Close()

		assert.Equal(t, 1, counter.count)
		count := fromDB(t, testDir, payloadRef)
		assert.Equal(t, uint16(1), count)
	})

	t.Run("ok - backoff ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		config := Config{Datadir: testDir, PayloadRetryDelay: 50 * time.Millisecond}
		counter := callbackCounter{}
		scheduler := NewPayloadScheduler(config.Datadir, config.PayloadRetryDelay, counter.callback)
		_ = scheduler.Configure()
		defer scheduler.Close()

		start := time.Now()
		err := scheduler.Schedule(payloadRef)

		if !assert.NoError(t, err) {
			return
		}

		counter.wait(2)

		// first try is immediate, second after 50 milliseconds
		assert.True(t, start.Add(50*time.Millisecond).Before(time.Now()))
	})
}

func TestPayloadScheduler_Start(t *testing.T) {
	payloadRef := hash.SHA256Sum([]byte("test"))

	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		config := Config{Datadir: testDir}
		counter := callbackCounter{}
		tenAsBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(tenAsBytes, 10)
		addToDB(t, testDir, payloadRef, tenAsBytes)
		scheduler := NewPayloadScheduler(config.Datadir, config.PayloadRetryDelay, counter.callback)
		_ = scheduler.Configure()

		err := scheduler.Start()
		if !assert.NoError(t, err) {
			return
		}

		counter.wait(1)

		// to enable access to DB
		scheduler.Close()

		assert.Equal(t, 1, counter.count)
		count := fromDB(t, testDir, payloadRef)
		assert.Equal(t, uint16(11), count)
	})
}

func TestPayloadScheduler_Remove(t *testing.T) {
	payloadRef := hash.SHA256Sum([]byte("test"))

	t.Run("ok - callback not called again", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		config := Config{Datadir: testDir, PayloadRetryDelay: 5 * time.Millisecond}
		counter := callbackCounter{}
		scheduler := NewPayloadScheduler(config.Datadir, config.PayloadRetryDelay, dummyCallback)
		scheduler.(*payloadScheduler).callback = func(_ hash.SHA256Hash) {
			_ = scheduler.Finished(payloadRef)
			counter.callback(hash.SHA256Hash{})
		}
		_ = scheduler.Configure()
		defer scheduler.Close()

		_ = scheduler.Schedule(payloadRef)
		counter.wait(1)

		// allow enough time for callback to not be called
		time.Sleep(10 * time.Millisecond)

		assert.Equal(t, 1, counter.count)
	})
}

func addToDB(t *testing.T, datadir string, hash hash.SHA256Hash, count []byte) {
	dbFile := path.Join(datadir, "network", "payload_jobs.db")
	if err := os.MkdirAll(filepath.Dir(dbFile), os.ModePerm); err != nil {
		t.Fatal(err)
	}

	db, err := bbolt.Open(dbFile, 0600, bbolt.DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("payload_jobs"))
		if err != nil {
			return err
		}
		return bucket.Put(hash.Slice(), count)
	})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
}

func fromDB(t *testing.T, datadir string, hash hash.SHA256Hash) (count uint16) {
	dbFile := path.Join(datadir, "network", "payload_jobs.db")
	if err := os.MkdirAll(filepath.Dir(dbFile), os.ModePerm); err != nil {
		t.Fatal(err)
	}

	db, err := bbolt.Open(dbFile, 0600, bbolt.DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("payload_jobs"))
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
