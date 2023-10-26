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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEciesEncrypt(t *testing.T) {
	key, err := generateECKeyPair()
	assert.NoError(t, err)

	cipherText1, err := EciesEncrypt(&key.PublicKey, []byte("hello world"))
	assert.NoError(t, err)

	cipherText2, err := EciesEncrypt(&key.PublicKey, []byte("hello world"))
	assert.NoError(t, err)

	assert.NotEqual(t, cipherText1, cipherText2)
}

func TestEciesDecrypt(t *testing.T) {
	key, err := generateECKeyPair()
	assert.NoError(t, err)

	cipherText, err := EciesEncrypt(&key.PublicKey, []byte("hello world"))
	assert.NoError(t, err)

	plainText, err := EciesDecrypt(key, cipherText)
	assert.NoError(t, err)

	assert.Equal(t, []byte("hello world"), plainText)
}

func generateECKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
