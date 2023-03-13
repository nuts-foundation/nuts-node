/*
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

package storage

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/redis7"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		require.NoError(t, err)

		store, err := db.createStore("unit", "test")
		require.NoError(t, err)
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
		require.NoError(t, err)

		store, err := db.createStore("unit", "test")
		require.NoError(t, err)
		defer store.Close(context.Background())

		// Assert: write some data and check keys
		_ = store.WriteShelf(context.Background(), "someshelf", func(writer stoabs.Writer) error {
			return writer.Put(stoabs.BytesKey(key), value)
		})
		keys := redis.Keys()
		assert.Equal(t, []string{"unit_test:someshelf.6d7367"}, keys)
	})
	t.Run("using redis.ParseURL() to connect over TLS", func(t *testing.T) {
		logrus.SetLevel(logrus.TraceLevel)

		// Setup server-side TLS
		cert, err := tls.LoadX509KeyPair("test/certificate.pem", "test/certificate.pem")
		require.NoError(t, err)
		redis, err := miniredis.RunTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
		})
		require.NoError(t, err)
		t.Cleanup(func() {
			redis.Close()
		})

		// Setup client-side TLS config
		redisTLSModifier = func(conf *tls.Config) {
			conf.InsecureSkipVerify = true
		}

		db, err := createRedisDatabase(RedisConfig{
			Address: "rediss://" + redis.Addr(),
			TLS: RedisTLSConfig{
				TrustStoreFile: "test/truststore.pem",
			},
		})
		require.NoError(t, err)

		store, err := db.createStore("unit", "test")
		require.NoError(t, err)
		_ = store.Close(context.Background())
	})
	t.Run("error - TLS configured, but not connecting to a TLS server", func(t *testing.T) {
		db, err := createRedisDatabase(RedisConfig{
			Address: "redis://test:1234",
			TLS: RedisTLSConfig{
				TrustStoreFile: "test/truststore.pem",
			},
		})
		assert.EqualError(t, err, "TLS configured but not connecting to a Redis TLS server")
		assert.Nil(t, db)
	})
	t.Run("Sentinel", func(t *testing.T) {
		t.Run("configure", func(t *testing.T) {
			db, err := createRedisDatabase(RedisConfig{
				Address: "rediss://foo",
				TLS: RedisTLSConfig{
					TrustStoreFile: "test/truststore.pem",
				},
				Username: "username",
				Password: "password",
				Sentinel: RedisSentinelConfig{
					Master: "master",
					Nodes: []string{
						"instance1:1234",
						"instance2:4321",
					},
					Username: "sentinel-user",
					Password: "sentinel-password",
				},
			})

			require.NoError(t, err)
			assert.NotNil(t, db.sentinelOptions)
			// Assert non-sentinel-specific options are still parsed
			assert.NotNil(t, db.sentinelOptions.TLSConfig)
			assert.Equal(t, "username", db.sentinelOptions.Username)
			assert.Equal(t, "password", db.sentinelOptions.Password)
			// Assert sentinel-specific options
			assert.Equal(t, "master", db.sentinelOptions.MasterName)
			assert.Empty(t, db.sentinelOptions.TLSConfig.ServerName)
			assert.Equal(t, []string{"instance1:1234", "instance2:4321"}, db.sentinelOptions.SentinelAddrs)
			assert.Equal(t, "sentinel-user", db.sentinelOptions.SentinelUsername)
			assert.Equal(t, "sentinel-password", db.sentinelOptions.SentinelPassword)
		})

		t.Run("error - master not configured", func(t *testing.T) {
			_, err := createRedisDatabase(RedisConfig{
				Address: "rediss://foo",
				Sentinel: RedisSentinelConfig{
					Nodes: []string{
						"instance1:1234",
						"instance2:4321",
					},
				},
			})

			assert.EqualError(t, err, "unable to configure Redis Sentinel client: master is not configured")
		})

		t.Run("error - nodes not configured", func(t *testing.T) {
			_, err := createRedisDatabase(RedisConfig{
				Address: "rediss://foo",
				Sentinel: RedisSentinelConfig{
					Master: "foo",
				},
			})

			assert.EqualError(t, err, "unable to configure Redis Sentinel client: node addresses are not configured")
		})

		t.Run("try to connect", func(t *testing.T) {
			// Setup server-side TLS
			cert, err := tls.LoadX509KeyPair("test/certificate.pem", "test/certificate.pem")
			require.NoError(t, err)
			redis, err := miniredis.RunTLS(&tls.Config{
				Certificates: []tls.Certificate{cert},
			})
			require.NoError(t, err)
			t.Cleanup(func() {
				redis.Close()
			})

			// Setup client-side TLS config
			redisTLSModifier = func(conf *tls.Config) {
				conf.InsecureSkipVerify = true
			}

			db, err := createRedisDatabase(RedisConfig{
				Address: "rediss://" + redis.Addr(),
				TLS: RedisTLSConfig{
					TrustStoreFile: "test/truststore.pem",
				},
				Sentinel: RedisSentinelConfig{
					Master: "master",
					Nodes:  []string{redis.Addr()},
				},
			})
			require.NoError(t, err)

			oldPingAttemptBackoff := redis7.PingAttemptBackoff
			defer func() {
				redis7.PingAttemptBackoff = oldPingAttemptBackoff
			}()
			redis7.PingAttemptBackoff = 0
			_, err = db.createStore("unit", "test")
			// We don't have Sentinel support in Miniredis, but we can check that the client attempted to connect using Sentinel
			assert.EqualError(t, err, "unable to connect to Redis database: database error: redis: all sentinels specified in configuration are unreachable")
		})
	})
}

func TestRedisConfig_IsConfigured(t *testing.T) {
	assert.False(t, RedisConfig{}.isConfigured())
	assert.True(t, RedisConfig{Address: "something"}.isConfigured())
}

func Test_redisDatabase_getClass(t *testing.T) {
	assert.Equal(t, Class(PersistentStorageClass), redisDatabase{}.getClass())
}
