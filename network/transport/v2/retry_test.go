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

func TestNewPayloadRetrier(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		retrier := NewPayloadRetrier(Config{}, dummyCallback)

		assert.NotNil(t, retrier)
		assert.NotNil(t, retrier.(*payloadRetrier).config)
		assert.NotNil(t, retrier.(*payloadRetrier).callback)
	})
}

func TestPayloadRetrier_Configure(t *testing.T) {
	t.Run("ok - default delay", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		config := Config{Datadir: testDir}
		retrier := NewPayloadRetrier(config, dummyCallback)

		err := retrier.Configure()

		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, retrier)
		assert.Equal(t, 5*time.Second, retrier.(*payloadRetrier).config.PayloadRetryDelay)
	})

	t.Run("error - invalid DB location", func(t *testing.T) {
		config := Config{Datadir: "retry_test.go"}
		retrier := NewPayloadRetrier(config, dummyCallback)

		err := retrier.Configure()

		assert.EqualError(t, err, "unable to setup database: mkdir retry_test.go: not a directory")
	})
}

type callbackCounter struct {
	count int
	wg    sync.WaitGroup
}

func (cc *callbackCounter) wait(count int) {
	if cc.count >= count {
		return
	}
	cc.wg.Add(count)
	cc.wg.Wait()
}

func (cc *callbackCounter) callback(_ hash.SHA256Hash) {
	cc.count++
	cc.wg.Done()
}

func TestPayloadRetrier_Add(t *testing.T) {
	payloadRef := hash.SHA256Sum([]byte("test"))

	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		config := Config{Datadir: testDir}
		counter := callbackCounter{}
		retrier := NewPayloadRetrier(config, counter.callback)
		_ = retrier.Configure()

		// also starts the go process
		err := retrier.Add(payloadRef)

		if !assert.NoError(t, err) {
			return
		}

		counter.wait(1)

		// to enable access to DB
		retrier.Close()

		assert.Equal(t, 1, counter.count)
		count := fromDB(t, testDir, payloadRef)
		assert.Equal(t, uint16(1), count)
	})

	t.Run("ok - backoff ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		config := Config{Datadir: testDir, PayloadRetryDelay: 50 * time.Millisecond}
		counter := callbackCounter{}
		retrier := NewPayloadRetrier(config, counter.callback)
		_ = retrier.Configure()
		defer retrier.Close()

		start := time.Now()
		err := retrier.Add(payloadRef)

		if !assert.NoError(t, err) {
			return
		}

		counter.wait(2)

		// first try is immediate, second after 50 milliseconds
		assert.True(t, start.Add(50*time.Millisecond).Before(time.Now()))
	})
}

func TestPayloadRetrier_Start(t *testing.T) {
	payloadRef := hash.SHA256Sum([]byte("test"))

	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		config := Config{Datadir: testDir}
		counter := callbackCounter{}
		tenAsBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(tenAsBytes, 10)
		addToDB(t, testDir, payloadRef, tenAsBytes)
		retrier := NewPayloadRetrier(config, counter.callback)
		_ = retrier.Configure()

		err := retrier.Start()
		if !assert.NoError(t, err) {
			return
		}

		counter.wait(1)

		// to enable access to DB
		retrier.Close()

		assert.Equal(t, 1, counter.count)
		count := fromDB(t, testDir, payloadRef)
		assert.Equal(t, uint16(11), count)
	})
}

func TestPayloadRetrier_Remove(t *testing.T) {
	payloadRef := hash.SHA256Sum([]byte("test"))

	t.Run("ok - callback not called again", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		config := Config{Datadir: testDir, PayloadRetryDelay: 5 * time.Millisecond}
		counter := callbackCounter{}
		retrier := NewPayloadRetrier(config, dummyCallback)
		retrier.(*payloadRetrier).callback = func(_ hash.SHA256Hash) {
			_ = retrier.Remove(payloadRef)
			counter.callback(hash.SHA256Hash{})
		}
		_ = retrier.Configure()
		defer retrier.Close()

		_ = retrier.Add(payloadRef)
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
