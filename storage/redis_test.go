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
	"crypto/x509"
	"github.com/alicebob/miniredis/v2"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
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
	t.Run("with TLS", func(t *testing.T) {
		logrus.SetLevel(logrus.TraceLevel)

		// Setup server-side TLS
		cert, err := tls.LoadX509KeyPair("test/certificate.pem", "test/certificate.pem")
		if !assert.NoError(t, err) {
			return
		}
		redis, err := miniredis.RunTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
		})
		if !assert.NoError(t, err) {
			return
		}
		t.Cleanup(func() {
			redis.Close()
		})

		// Setup client-side TLS config
		rootCA, _ := ioutil.ReadFile("test/truststore.pem")
		defaultRedisTLSConfig.InsecureSkipVerify = true
		defaultRedisTLSConfig.RootCAs = x509.NewCertPool()
		defaultRedisTLSConfig.RootCAs.AppendCertsFromPEM(rootCA)

		db, err := createRedisDatabase(RedisConfig{Address: redis.Addr(), Database: "db", TLSEnabled: true})
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
}

func TestRedisConfig_IsConfigured(t *testing.T) {
	assert.False(t, RedisConfig{}.IsConfigured())
	assert.True(t, RedisConfig{Address: "something"}.IsConfigured())
}

func Test_redisDatabase_getClass(t *testing.T) {
	assert.Equal(t, Class(PersistentStorageClass), redisDatabase{}.getClass())
}
