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
 */

package util

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"os"
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/test"

	"github.com/stretchr/testify/assert"
)

func TestCrypto_PublicKeyToPem(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		key := test.GenerateRSAKey()
		result, err := PublicKeyToPem(&key.PublicKey)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Contains(t, result, "-----BEGIN PUBLIC KEY-----")
		assert.Contains(t, result, "-----END PUBLIC KEY-----")
		decoded, rest := pem.Decode([]byte(result))
		assert.Len(t, rest, 0)
		assert.NotNil(t, decoded)
	})
	t.Run("wrong public key gives error", func(t *testing.T) {
		_, err := PublicKeyToPem(&rsa.PublicKey{})
		assert.Error(t, err)
	})
}

func TestCrypto_pemToPublicKey(t *testing.T) {
	t.Run("wrong PEM block gives error", func(t *testing.T) {
		_, err := PemToPublicKey([]byte{})

		assert.Equal(t, ErrWrongPublicKey, err)
	})

	t.Run("converts public key", func(t *testing.T) {
		pem := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEny33KMxU+mtPxSBMIztm69lehhNo\nCQD632dFAYSzDGh2LqemmYx9EKFzuzvCqbw87BD3spzbakjj5R315qV0gw==\n-----END PUBLIC KEY-----"

		pk, err := PemToPublicKey([]byte(pem))
		require.NoError(t, err)

		assert.IsType(t, &ecdsa.PublicKey{}, pk)
	})

	t.Run("converts RSA public key", func(t *testing.T) {
		pem := "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAMXC7V5p/LRULNuRWNBBcizjCrMPIV57LjNG6RCpkJsFtTfw5Ra+aGFJ\nmoEjlSrOsJ1aRO2krR4UTCijOrv1JNFjCvv81urSK9xSUAXzQcPdogf051ZDt1Ct\nEv4ETZQkXDMibzlbmgXq1V+oib4FXDCk0Emu6SAfOGmov/V9eShNAgMBAAE=\n-----END RSA PUBLIC KEY-----"

		pk, err := PemToPublicKey([]byte(pem))
		require.NoError(t, err)

		assert.IsType(t, &rsa.PublicKey{}, pk)
	})
}

func TestPemToSigner(t *testing.T) {
	t.Run("Convert ED25519 key", func(t *testing.T) {
		pem, _ := os.ReadFile("../test/ed25519.sk")
		signer, err := PemToPrivateKey(pem)
		assert.NoError(t, err)
		assert.NotNil(t, signer)
	})

	t.Run("Convert EC key (stdlib)", func(t *testing.T) {
		pem, _ := os.ReadFile("../test/ec.sk")
		signer, err := PemToPrivateKey(pem)
		assert.NoError(t, err)
		assert.NotNil(t, signer)
	})

	t.Run("Convert secp256k1 key", func(t *testing.T) {

	})

	t.Run("Convert RSA key", func(t *testing.T) {
		pem, _ := os.ReadFile("../test/rsa.sk")
		signer, err := PemToPrivateKey(pem)
		assert.NoError(t, err)
		assert.NotNil(t, signer)
	})

	t.Run("Convert PKIX key", func(t *testing.T) {
		pem, _ := os.ReadFile("../test/sk.pem")
		signer, err := PemToPrivateKey(pem)
		assert.NoError(t, err)
		assert.NotNil(t, signer)
	})

	t.Run("Convert garbage", func(t *testing.T) {
		_, err := PemToPrivateKey([]byte{})
		require.ErrorIs(t, err, ErrWrongPrivateKey)
	})
}

func TestPrivateKeyToPem(t *testing.T) {
	t.Run("secp256k1", func(t *testing.T) {
		const expectedPEM = ``
		privKeyBytes, err := base64.StdEncoding.DecodeString("Kuy/wuUXMU2IiI2V71Ycr/slu+HKz86FF5vwXl/bqtg=")
		require.NoError(t, err)
		expectedPrivKey := secp256k1.PrivKeyFromBytes(privKeyBytes)

		actual, err := PrivateKeyToPem(expectedPrivKey)
		t.Log(actual)
		require.NoError(t, err)
		assert.Equal(t, expectedPEM, actual)
	})
}
