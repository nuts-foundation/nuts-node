package storage

import (
	"context"
	"github.com/alicebob/miniredis/v2"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_redisDatabase_createStore(t *testing.T) {
	const key = "msg"
	value := []byte("Hello, World!")

	t.Run("with database prefix", func(t *testing.T) {
		redis := miniredis.RunT(t)
		t.Cleanup(func() {
			redis.Close()
		})

		db, err := createRedisDatabase(RedisConfig{Address: redis.Addr(), Database: "db"})
		if !assert.NoError(t, err) {
			return
		}

		store, err := db.createStore("unit", "test")
		if !assert.NoError(t, err) {
			return
		}
		defer store.Close(context.Background())

		// Assert: write some data and check keys
		_ = store.WriteShelf(context.Background(), "someshelf", func(writer stoabs.Writer) error {
			return writer.Put(stoabs.BytesKey(key), value)
		})
		keys := redis.Keys()
		assert.Equal(t, []string{"db_unit_test:someshelf.6d7367"}, keys)
	})
	t.Run("without database prefix", func(t *testing.T) {
		redis := miniredis.RunT(t)
		t.Cleanup(func() {
			redis.Close()
		})

		db, err := createRedisDatabase(RedisConfig{Address: redis.Addr()})
		if !assert.NoError(t, err) {
			return
		}

		store, err := db.createStore("unit", "test")
		if !assert.NoError(t, err) {
			return
		}
		defer store.Close(context.Background())

		// Assert: write some data and check keys
		_ = store.WriteShelf(context.Background(), "someshelf", func(writer stoabs.Writer) error {
			return writer.Put(stoabs.BytesKey(key), value)
		})
		keys := redis.Keys()
		assert.Equal(t, []string{"unit_test:someshelf.6d7367"}, keys)
	})
}

func TestRedisConfig_IsConfigured(t *testing.T) {
	assert.False(t, RedisConfig{}.IsConfigured())
	assert.True(t, RedisConfig{Address: "something"}.IsConfigured())
}

func Test_redisDatabase_getClass(t *testing.T) {
	assert.Equal(t, Class(PersistentStorageClass), redisDatabase{}.getClass())
}
