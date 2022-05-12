package storage

import (
	"errors"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"path"
	"testing"
)

var key = []byte{1, 2, 3}
var value = []byte{4, 5, 6}

const bucket = "test"

func TestBBolt_Write(t *testing.T) {
	t.Run("write, then read", func(t *testing.T) {
		store, _ := createBBoltStore(path.Join(io.TestDirectory(t), "bbolt.db"), nil)
		defer store.Close()

		err := store.Write(func(tx WriteTransaction) error {
			bucket, err := tx.Bucket(bucket)
			if err != nil {
				return err
			}
			return bucket.Put(key, value)
		})

		var actual []byte
		err = store.ReadBucket(bucket, func(reader BucketReader) error {
			actual, err = reader.Get(key)
			return err
		})
		assert.NoError(t, err)
		assert.Equal(t, value, actual)
	})
}

func TestBBolt_Read(t *testing.T) {
	t.Run("non-existing bucket", func(t *testing.T) {
		store, _ := createBBoltStore(path.Join(io.TestDirectory(t), "bbolt.db"), nil)
		defer store.Close()

		err := store.Read(func(tx ReadTransaction) error {
			bucket, err := tx.Bucket(bucket)
			if err != nil {
				return err
			}
			if bucket == nil {
				return nil
			}
			t.Fatal()
			return nil
		})
		assert.NoError(t, err)
	})
}

func TestBBolt_WriteBucket(t *testing.T) {
	t.Run("write, then read", func(t *testing.T) {
		store, _ := createBBoltStore(path.Join(io.TestDirectory(t), "bbolt.db"), nil)
		defer store.Close()

		// First write
		err := store.WriteBucket(bucket, func(writer BucketWriter) error {
			return writer.Put(key, value)
		})
		if !assert.NoError(t, err) {
			return
		}

		// Now read
		var actual []byte
		err = store.ReadBucket(bucket, func(reader BucketReader) error {
			actual, err = reader.Get(key)
			return err
		})
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, value, actual)
	})
	t.Run("rollback on application error", func(t *testing.T) {
		store, _ := createBBoltStore(path.Join(io.TestDirectory(t), "bbolt.db"), nil)
		defer store.Close()

		err := store.WriteBucket(bucket, func(writer BucketWriter) error {
			err := writer.Put(key, value)
			if err != nil {
				panic(err)
			}
			return errors.New("failed")
		})
		assert.EqualError(t, err, "failed")

		// Now assert the TX was rolled back
		var actual []byte
		err = store.ReadBucket(bucket, func(reader BucketReader) error {
			actual, err = reader.Get(key)
			return err
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.Nil(t, actual)
	})
}

func TestBBolt_ReadBucket(t *testing.T) {
	t.Run("read from non-existing bucket", func(t *testing.T) {
		store, _ := createBBoltStore(path.Join(io.TestDirectory(t), "bbolt.db"), nil)
		defer store.Close()

		called := false
		err := store.ReadBucket(bucket, func(reader BucketReader) error {
			called = true
			return nil
		})

		assert.NoError(t, err)
		assert.False(t, called)
	})
}

func TestBBolt_Close(t *testing.T) {
	t.Run("close closed store", func(t *testing.T) {
		store, _ := createBBoltStore(path.Join(io.TestDirectory(t), "bbolt.db"), nil)
		assert.NoError(t, store.Close())
		assert.NoError(t, store.Close())
	})
}
