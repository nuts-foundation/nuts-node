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
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"testing"
)

// NewMemoryCryptoInstance returns a new Crypto instance to be used for tests, storing keys in-memory and creating a new SQL DB.
func NewMemoryCryptoInstance(t *testing.T) *Crypto {
	return NewTestCryptoInstance(orm.NewTestDatabase(t), NewMemoryStorage())
}

// NewDatabaseCryptoInstance returns a new Crypto instance to be used for tests, storing keys in-memory and the given DB.
func NewDatabaseCryptoInstance(db *gorm.DB) *Crypto {
	return NewTestCryptoInstance(db, NewMemoryStorage())
}

// NewTestCryptoInstance returns a new Crypto instance to be used for tests, allowing to use of preconfigured backend.
func NewTestCryptoInstance(db *gorm.DB, storage spi.Storage) *Crypto {
	newInstance := NewCryptoInstance(nil)
	newInstance.backend = storage
	newInstance.db = db
	return newInstance
}

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

func (m memoryStorage) NewPrivateKey(ctx context.Context, keyName string) (crypto.PublicKey, string, error) {
	return spi.GenerateAndStore(ctx, m, keyName)
}

func (m memoryStorage) Name() string {
	return "memory"
}

func (m memoryStorage) CheckHealth() map[string]core.Health {
	return map[string]core.Health{"memory": {Status: core.HealthStatusUp}}
}

func (m memoryStorage) ListPrivateKeys(_ context.Context) []spi.KeyNameVersion {
	var result []spi.KeyNameVersion
	for key := range m {
		result = append(result, spi.KeyNameVersion{KeyName: key, Version: "1"})
	}
	return result
}

func (m memoryStorage) GetPrivateKey(_ context.Context, keyName string, _ string) (crypto.Signer, error) {
	pk, ok := m[keyName]
	if !ok {
		return nil, ErrPrivateKeyNotFound
	}
	return pk.(crypto.Signer), nil
}

func (m memoryStorage) PrivateKeyExists(_ context.Context, keyName string, _ string) (bool, error) {
	_, ok := m[keyName]
	return ok, nil
}

func (m memoryStorage) DeletePrivateKey(_ context.Context, keyName string) error {
	_, ok := m[keyName]
	if !ok {
		return ErrPrivateKeyNotFound
	}
	delete(m, keyName)
	return nil
}

func (m memoryStorage) SavePrivateKey(_ context.Context, kid string, key crypto.PrivateKey) error {
	m[kid] = key
	return nil
}

// NewTestKey creates a new TestKey with a given kid
func NewTestKey(kid string) *TestKey {
	keyPair, _ := spi.GenerateKeyPair()
	return &TestKey{
		KID:        kid,
		PublicKey:  keyPair.Public(),
		PrivateKey: keyPair,
	}
}

// TestKey is a Key impl for testing purposes
type TestKey struct {
	KID        string
	PublicKey  crypto.PublicKey
	PrivateKey crypto.Signer
}

func (t TestKey) Signer() crypto.Signer {
	return t.PrivateKey
}

func (t TestKey) Private() crypto.PrivateKey {
	return t.PrivateKey
}

// newKeyReference creates a new DID, DIDocument, VerificationMethod and KeyReference in the DB
// It does not create valid DID Document data
func newKeyReference(t *testing.T, client *Crypto, kid string) (*orm.KeyReference, crypto.PublicKey) {
	ref, publicKey, err := client.New(audit.TestContext(), StringNamingFunc(kid))
	require.NoError(t, err)
	DID := orm.DID{ID: "did:test:" + t.Name(), Subject: "subject"}
	DIDDoc := orm.DIDDocument{
		DID: DID,
		VerificationMethods: []orm.VerificationMethod{
			{
				ID:   kid,
				Data: []byte("{}"),
			},
		},
	}
	require.NoError(t, client.db.Save(&DIDDoc).Error)
	return ref, publicKey
}
