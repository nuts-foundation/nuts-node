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
	"encoding/pem"
	"github.com/stretchr/testify/require"
	"os"
	"path"
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

func TestPrivateKeyMarshalling(t *testing.T) {
	type testCase struct {
		file string
		err  string
	}

	testCases := []testCase{
		{
			file: "../test/private_rsa2048_pkcs1.pem",
		},
		{
			file: "../test/private_rsa1024_pkcs8.pem",
		},
		{
			file: "../test/private_ed25519_pkcs8.pem",
		},
		{
			file: "../test/private_secp256k1_asn1_echeader.pem",
		},
		{
			file: "../test/private_secp256k1_asn1.pem",
		},
		{
			file: "../test/private_secp256r1_asn1_echeader.pem",
		},
		{
			file: "../test/private_secp256r1_asn1.pem",
		},
		{
			file: "../test/private_secp256r1_pkcs8.pem",
		},
		{
			file: "../test/private_invalid_key.pem",
			err:  "failed to decode PEM block containing private key\nasn1: structure error: length too large",
		},
	}

	for _, testCase := range testCases {
		t.Run(path.Base(testCase.file), func(t *testing.T) {
			pemData, err := os.ReadFile(testCase.file)
			require.NoError(t, err)
			expectedKey, err := PemToPrivateKey(pemData)

			if testCase.err != "" {
				assert.EqualError(t, err, testCase.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, expectedKey)

				marshalledPEM, err := PrivateKeyToPem(expectedKey)
				require.NoError(t, err)
				require.NotNil(t, marshalledPEM)

				actualKey, err := PemToPrivateKey(pemData)
				require.NoError(t, err)
				require.NotNil(t, actualKey)
				require.Equal(t, expectedKey, actualKey)
			}
		})
	}
}

func TestPemToPrivateKey(t *testing.T) {
	t.Run("garbage", func(t *testing.T) {
		_, err := PemToPrivateKey([]byte{})
		require.ErrorIs(t, err, ErrWrongPrivateKey)
	})
}
