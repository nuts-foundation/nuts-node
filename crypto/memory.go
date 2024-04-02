/*
 * Copyright (C) 2024 Nuts community
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
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

var _ KeyStore = &MemoryKeyStore{}
var errNotSupportedForInMemoryKeyStore = errors.New("not supported on in-memory key store")

// MemoryKeyStore is a KeyStore implementation that performs cryptographic operations on an in-memory JWK.
// This should only be used for low-assurance use cases, e.g. session-bound user keys.
type MemoryKeyStore struct {
	Key jwk.Key
}

func (m MemoryKeyStore) Resolve(_ context.Context, kid string) (Key, error) {
	if kid != m.Key.KeyID() {
		return nil, ErrPrivateKeyNotFound
	}
	var publicKey crypto.PublicKey
	publicJWK, err := m.Key.PublicKey()
	if err != nil {
		return nil, err
	}
	if err := publicJWK.Raw(&publicKey); err != nil {
		return nil, err
	}
	return &basicKey{
		publicKey: publicKey,
		kid:       m.Key.KeyID(),
	}, nil
}

func (m MemoryKeyStore) SignJWT(_ context.Context, claims map[string]interface{}, headers map[string]interface{}, rawKey interface{}) (string, error) {
	key, _ := rawKey.(Key)
	if key == nil {
		return "", errors.New("key should be crypto.Key")
	}
	if key.KID() != m.Key.KeyID() {
		return "", ErrPrivateKeyNotFound
	}
	return signJWT(m.Key, claims, headers)
}

func (m MemoryKeyStore) List(_ context.Context) []string {
	return []string{m.Key.KeyID()}
}

func (m MemoryKeyStore) Exists(_ context.Context, kid string) bool {
	return kid == m.Key.KeyID()
}

func (m MemoryKeyStore) SignJWS(_ context.Context, _ []byte, _ map[string]interface{}, _ interface{}, _ bool) (string, error) {
	return "", errNotSupportedForInMemoryKeyStore
}

func (m MemoryKeyStore) Decrypt(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, errNotSupportedForInMemoryKeyStore
}

func (m MemoryKeyStore) New(_ context.Context, _ KIDNamingFunc) (Key, error) {
	return nil, errNotSupportedForInMemoryKeyStore
}

func (m MemoryKeyStore) EncryptJWE(_ context.Context, _ []byte, _ map[string]interface{}, _ interface{}) (string, error) {
	return "", errNotSupportedForInMemoryKeyStore
}

func (m MemoryKeyStore) DecryptJWE(_ context.Context, _ string) (body []byte, headers map[string]interface{}, err error) {
	return nil, nil, errNotSupportedForInMemoryKeyStore
}

func (m MemoryKeyStore) Delete(_ context.Context, _ string) error {
	return errNotSupportedForInMemoryKeyStore
}
