package storage

import (
	"os"
	"testing"
	"time"

	jwk "github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/test"
	"github.com/nuts-foundation/nuts-node/test/io"

	"github.com/stretchr/testify/assert"
)

func Test_NewFileSystemBackend(t *testing.T) {
	t.Run("error - path is empty", func(t *testing.T) {
		storage, err := NewFileSystemBackend("")
		assert.EqualError(t, err, "filesystem path is empty")
		assert.Nil(t, storage)
	})
}

func Test_fs_GetPublicKey(t *testing.T) {
	t.Run("non-existing entry", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		_, err := storage.GetPublicKey("unknown")
		assert.Contains(t, err.Error(), "could not open entry unknown with filename")
	})
	t.Run("ok", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		ec := test.GenerateECKey()
		kid := "kid"
		now := time.Now()
		pke := &PublicKeyEntry{Period: core.Period{ValidFrom: now}}
		key, _ := jwk.New(ec.Public())
		pke.FromJWK(key)

		err := storage.SavePublicKey(kid, *pke)
		if !assert.NoError(t, err) {
			return
		}

		entry, err := storage.GetPublicKey(kid)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, key, entry.JWK())
		assert.Equal(t, time.Duration(0), now.Sub(entry.Period.ValidFrom))
	})
}

func Test_fs_GetPrivateKey(t *testing.T) {
	t.Run("non-existing entry", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))

		key, err := storage.GetPrivateKey("unknown")

		assert.Contains(t, err.Error(), "could not open entry unknown with filename")
		assert.Nil(t, key)
	})
	t.Run("private key invalid", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		kid := "kid"
		path := storage.(*fileSystemBackend).getEntryPath(kid, privateKeyEntry)
		file, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
		_, err := file.WriteString("hello world")
		if !assert.NoError(t, err) {
			return
		}

		key, err := storage.GetPrivateKey(kid)

		assert.Nil(t, key)
		assert.Error(t, err)
	})
	t.Run("ok", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		pk := test.GenerateECKey()
		kid := "kid"

		err := storage.SavePrivateKey(kid, pk)
		if !assert.NoError(t, err) {
			return
		}

		key, err := storage.GetPrivateKey(kid)

		assert.NoError(t, err)
		if !assert.NotNil(t, key) {
			return
		}
		assert.Equal(t, pk, key)
	})
}

func Test_fs_KeyExistsFor(t *testing.T) {
	t.Run("non-existing entry", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		assert.False(t, storage.PrivateKeyExists("unknown"))
	})
	t.Run("existing entry", func(t *testing.T) {
		storage, _ := NewFileSystemBackend(io.TestDirectory(t))
		pk := test.GenerateECKey()
		kid := "kid"
		storage.SavePrivateKey(kid, pk)
		assert.True(t, storage.PrivateKeyExists(kid))
	})
}
