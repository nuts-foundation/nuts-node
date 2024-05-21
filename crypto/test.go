/*
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

package crypto

import (
	"context"
	"crypto"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	log "github.com/sirupsen/logrus"
)

// NewMemoryCryptoInstance returns a new Crypto instance to be used for tests, storing keys in-memory.
func NewMemoryCryptoInstance() *Crypto {
	return NewTestCryptoInstance(NewMemoryStorage())
}

// NewTestCryptoInstance returns a new Crypto instance to be used for tests, allowing to use of preconfigured storage.
func NewTestCryptoInstance(storage spi.Storage) *Crypto {
	newInstance := NewCryptoInstance()
	newInstance.storage = storage
	return newInstance
}

// StringNamingFunc can be used to give a key a simple string name
func StringNamingFunc(name string) KIDNamingFunc {
	return func(key crypto.PublicKey) (string, error) {
		return name, nil
	}
}

func ErrorNamingFunc(err error) KIDNamingFunc {
	return func(key crypto.PublicKey) (string, error) {
		return "", err
	}
}

func NewMemoryStorage() spi.Storage {
	return memoryStorage{}
}

var _ spi.Storage = &memoryStorage{}

type memoryStorage map[string]crypto.PrivateKey

func (m memoryStorage) NewPrivateKey(ctx context.Context, namingFunc func(crypto.PublicKey) (string, error)) (crypto.PublicKey, string, error) {
	return spi.GenerateAndStore(ctx, m, namingFunc)
}

func (m memoryStorage) Name() string {
	return "memory"
}

func (m memoryStorage) CheckHealth() map[string]core.Health {
	return map[string]core.Health{"memory": {Status: core.HealthStatusUp}}
}

func (m memoryStorage) ListPrivateKeys(_ context.Context) []string {
	var result []string
	for key := range m {
		result = append(result, key)
	}
	return result
}

func (m memoryStorage) GetPrivateKey(_ context.Context, kid string) (crypto.Signer, error) {
	pk, ok := m[kid]
	if !ok {
		return nil, ErrPrivateKeyNotFound
	}
	return pk.(crypto.Signer), nil
}

func (m memoryStorage) PrivateKeyExists(_ context.Context, kid string) (bool, error) {
	_, ok := m[kid]
	return ok, nil
}

func (m memoryStorage) DeletePrivateKey(_ context.Context, kid string) error {
	_, ok := m[kid]
	if !ok {
		return ErrPrivateKeyNotFound
	}
	delete(m, kid)
	return nil
}

func (m memoryStorage) SavePrivateKey(_ context.Context, kid string, key crypto.PrivateKey) error {
	m[kid] = key
	return nil
}

func NewTestKey(kid string) *TestKey {
	key, err := NewEphemeralKey(func(key crypto.PublicKey) (string, error) {
		return kid, nil
	})
	if err != nil {
		log.Fatal(err.Error())
	}
	return &TestKey{
		Kid:        kid,
		PrivateKey: key.(*memoryKey).privateKey,
	}
}

// TestKey is a Key impl for testing purposes
type TestKey struct {
	PrivateKey crypto.Signer
	Kid        string
}

func (t TestKey) Signer() crypto.Signer {
	return t.PrivateKey
}

func (t TestKey) KID() string {
	return t.Kid
}

func (t TestKey) Public() crypto.PublicKey {
	return t.PrivateKey.Public()
}

func (t TestKey) Private() crypto.PrivateKey {
	return t.PrivateKey
}

// TestPublicKey is a Key impl for testing purposes that only contains a public key. It can't be used for signing.
type TestPublicKey struct {
	Kid       string
	PublicKey crypto.PublicKey
}

func (t TestPublicKey) Signer() crypto.Signer {
	panic("test public key is not for signing")
}

func (t TestPublicKey) KID() string {
	return t.Kid
}

func (t TestPublicKey) Public() crypto.PublicKey {
	return t.PublicKey
}

func (t TestPublicKey) Private() crypto.PrivateKey {
	panic("test public key is not for signing")
}
