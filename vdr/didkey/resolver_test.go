/*
 * Copyright (C) 2023 Nuts community
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

package didkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multicodec"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTestVectors(t *testing.T) {
	resolver := Resolver{}
	type testCase struct {
		name  string
		did   string
		jwk   map[string]interface{}
		error string
	}

	unsafeRSAKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	unsafeRSAKeyBytes := x509.MarshalPKCS1PublicKey(&unsafeRSAKey.PublicKey)

	testCases := []testCase{
		// Taken from https://w3c-ccg.github.io/did-method-key/#ed25519-x25519
		{
			name: "ed25519",
			did:  "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
			jwk: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
			},
		},
		{
			name:  "ed25519 (invalid length)",
			did:   createDIDKey(multicodec.Ed25519Pub, []byte{1, 2, 3}),
			error: "invalid did:key: invalid public key length",
		},
		// Taken from https://w3c-ccg.github.io/did-method-key/#x25519
		{
			name: "x25519",
			did:  "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F",
			jwk: map[string]interface{}{
				"crv": "X25519",
				"kty": "OKP",
				"x":   "L-V9o0fNYkMVKNqsX7spBzD_9oSvxM_C7ZCZX1jLO3Q",
			},
		},
		{
			name:  "x25519 (invalid length)",
			did:   createDIDKey(multicodec.X25519Pub, []byte{1, 2, 3}),
			error: "invalid did:key: invalid public key length",
		},
		// Taken from https://w3c-ccg.github.io/did-method-key/#secp256k1
		{
			name:  "secp256k1",
			did:   "did:key:zQ3shbgnTGcgBpXPdBjDur3ATMDWhS7aPs6FRFkWR19Lb9Zwz",
			error: "did:key: secp256k1 public keys are not supported",
		},
		// Taken from https://w3c-ccg.github.io/did-method-key/#bls-12381
		{
			name:  "bls12381",
			did:   "did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY",
			error: "did:key: bls12381 public keys are not supported",
		},
		// Taken from https://w3c-ccg.github.io/did-method-key/#p-256
		{
			name: "secp256",
			did:  "did:key:zDnaeucDGfhXHoJVqot3p21RuupNJ2fZrs8Lb1GV83VnSo2jR",
			jwk: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "sYLQHOy9TNAWwFcAlpxkqRA5OutpWCrVPEWsgeli_KA",
				"y":   "l5Jr9_48oPJWHwuVmH_VZVquGe-U8RtnR-McN4tdYhs",
			},
		},
		{
			name:  "secp256 (invalid length)",
			did:   createDIDKey(multicodec.P256Pub, []byte{1, 2, 3}),
			error: "invalid did:key: invalid public key length",
		},
		// Taken from https://w3c-ccg.github.io/did-method-key/#p-384
		{
			name: "secp384",
			did:  "did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9",
			jwk: map[string]interface{}{
				"kty": "EC",
				"crv": "P-384",
				"x":   "lInTxl8fjLKp_UCrxI0WDklahi-7-_6JbtiHjiRvMvhedhKVdHBfi2HCY8t_QJyc",
				"y":   "y6N1IC-2mXxHreETBW7K3mBcw0qGr3CWHCs-yl09yCQRLcyfGv7XhqAngHOu51Zv",
			},
		},
		{
			name:  "secp384 (invalid length)",
			did:   createDIDKey(multicodec.P384Pub, []byte{1, 2, 3}),
			error: "invalid did:key: invalid public key length",
		},
		// Taken from https://w3c-ccg.github.io/did-method-key/#p-521
		{
			name: "secp521",
			did:  "did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7",
			jwk: map[string]interface{}{
				"kty": "EC",
				"crv": "P-521",
				"x":   "ASUHPMyichQ0QbHZ9ofNx_l4y7luncn5feKLo3OpJ2nSbZoC7mffolj5uy7s6KSKXFmnNWxGJ42IOrjZ47qqwqyS",
				"y":   "AW9ziIC4ZQQVSNmLlp59yYKrjRY0_VqO-GOIYQ9tYpPraBKUloEId6cI_vynCzlZWZtWpgOM3HPhYEgawQ703RjC",
			},
		},
		// Taken from https://w3c-ccg.github.io/did-method-key/#rsa-2048
		{
			name: "rsa2048",
			did:  "did:key:z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i",
			jwk: map[string]interface{}{
				"kty": "RSA",
				"e":   "AQAB",
				"n":   "sbX82NTV6IylxCh7MfV4hlyvaniCajuP97GyOqSvTmoEdBOflFvZ06kR_9D6ctt45Fk6hskfnag2GG69NALVH2o4RCR6tQiLRpKcMRtDYE_thEmfBvDzm_VVkOIYfxu-Ipuo9J_S5XDNDjczx2v-3oDh5-CIHkU46hvFeCvpUS-L8TJSbgX0kjVk_m4eIb9wh63rtmD6Uz_KBtCo5mmR4TEtcLZKYdqMp3wCjN-TlgHiz_4oVXWbHUefCEe8rFnX1iQnpDHU49_SaXQoud1jCaexFn25n-Aa8f8bc5Vm-5SeRwidHa6ErvEhTvf1dz6GoNPp2iRvm-wJ1gxwWJEYPQ",
			},
		},
		// Taken from https://w3c-ccg.github.io/did-method-key/#rsa-4096
		{
			name: "rsa4096",
			did:  "did:key:zgghBUVkqmWS8e1ioRVp2WN9Vw6x4NvnE9PGAyQsPqM3fnfPf8EdauiRVfBTcVDyzhqM5FFC7ekAvuV1cJHawtfgB9wDcru1hPDobk3hqyedijhgWmsYfJCmodkiiFnjNWATE7PvqTyoCjcmrc8yMRXmFPnoASyT5beUd4YZxTE9VfgmavcPy3BSouNmASMQ8xUXeiRwjb7xBaVTiDRjkmyPD7NYZdXuS93gFhyDFr5b3XLg7Rfj9nHEqtHDa7NmAX7iwDAbMUFEfiDEf9hrqZmpAYJracAjTTR8Cvn6mnDXMLwayNG8dcsXFodxok2qksYF4D8ffUxMRmyyQVQhhhmdSi4YaMPqTnC1J6HTG9Yfb98yGSVaWi4TApUhLXFow2ZvB6vqckCNhjCRL2R4MDUSk71qzxWHgezKyDeyThJgdxydrn1osqH94oSeA346eipkJvKqYREXBKwgB5VL6WF4qAK6sVZxJp2dQBfCPVZ4EbsBQaJXaVK7cNcWG8tZBFWZ79gG9Cu6C4u8yjBS8Ux6dCcJPUTLtixQu4z2n5dCsVSNdnP1EEs8ZerZo5pBgc68w4Yuf9KL3xVxPnAB1nRCBfs9cMU6oL1EdyHbqrTfnjE8HpY164akBqe92LFVsk8RusaGsVPrMekT8emTq5y8v8CabuZg5rDs3f9NPEtogjyx49wiub1FecM5B7QqEcZSYiKHgF4mfkteT2",
			jwk: map[string]interface{}{
				"kty": "RSA",
				"e":   "AQAB",
				"n":   "qMCkFFRFWtzUyZeK8mgJdyM6SEQcXC5E6JwCRVDld-jlJs8sXNOE_vliexq34wZRQ4hk53-JPFlvZ_QjRgIxdUxSMiZ3S5hlNVvvRaue6SMakA9ugQhnfXaWORro0UbPuHLms-bg5StDP8-8tIezu9c1H1FjwPcdbV6rAvKhyhnsM10qP3v2CPbdE0q3FOsihoKuTelImtO110E7N6fLn4U3EYbC4OyViqlrP1o_1M-R-tiM1cb4pD7XKJnIs6ryZdfOQSPBJwjNqSdN6Py_tdrFgPDTyacSSdpTVADOM2IMAoYbhV1N5APhnjOHBRFyKkF1HffQKpmXQLBqvUNNjuhmpVKWBtrTdcCKrglFXiw0cKGHKxIirjmiOlB_HYHg5UdosyE3_1Txct2U7-WBB6QXak1UgxCzgKYBDI8UPA0RlkUuHHP_Zg0fVXrXIInHO04MYxUeSps5qqyP6dJBu_v_BDn3zUq6LYFwJ_-xsU7zbrKYB4jaRlHPoCj_eDC-rSA2uQ4KXHBB8_aAqNFC9ukWxc26Ifz9dF968DLuL30bi-ZAa2oUh492Pw1bg89J7i4qTsOOfpQvGyDV7TGhKuUG3Hbumfr2w16S-_3EI2RIyd1nYsflE6ZmCkZQMG_lwDAFXaqfyGKEDouJuja4XH8r4fGWeGTrozIoniXT1HU",
			},
		},
		{
			name:  "rsa (invalid key)",
			did:   createDIDKey(multicodec.RsaPub, []byte{1, 2, 3}),
			error: "did:key: invalid PKCS#1 encoded RSA public key: asn1: structure error: tags don't match (16 vs {class:0 tag:1 length:2 isCompound:false}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} pkcs1PublicKey @2",
		},
		{
			name:  "rsa (key too small)",
			did:   createDIDKey(multicodec.RsaPub, unsafeRSAKeyBytes),
			error: "did:key: RSA public key is too small (must be at least 2048 bits)",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			doc, md, err := resolver.Resolve(did.MustParseDID(tc.did), nil)
			if tc.error != "" {
				require.EqualError(t, err, tc.error)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, doc)
			require.NotNil(t, md)
			// Assert getting the public key
			vm := doc.VerificationMethod[0]
			publicKey, err := vm.PublicKey()
			require.NoError(t, err, "failed to get public key")
			require.NotNil(t, publicKey, "public key is nil")
			// Assert JWK type
			jwk, err := vm.JWK()

			require.NoError(t, err, "failed to get JWK")
			jwkJSON, _ := json.Marshal(jwk)
			var jwkAsMap map[string]interface{}
			_ = json.Unmarshal(jwkJSON, &jwkAsMap)
			assert.Equal(t, tc.jwk, jwkAsMap)
		})
	}
}

func TestResolver_Resolve(t *testing.T) {
	t.Run("did:key ID does not start with 'z' (invalid multibase encoding)", func(t *testing.T) {
		_, _, err := Resolver{}.Resolve(did.MustParseDID("did:key:foo"), nil)
		require.EqualError(t, err, "did:key does not start with 'z'")
	})
	t.Run("did:key ID is not valid base58btc encoded 'z'", func(t *testing.T) {
		_, _, err := Resolver{}.Resolve(did.MustParseDID("did:key:z291830129"), nil)
		require.EqualError(t, err, "did:key: invalid base58btc: invalid base58 string")
	})
	t.Run("invalid multicodec key type", func(t *testing.T) {
		_, _, err := Resolver{}.Resolve(did.MustParseDID("did:key:z"), nil)
		require.EqualError(t, err, "did:key: invalid multicodec value: EOF")
	})
	t.Run("unsupported key type", func(t *testing.T) {
		didKey := createDIDKey(multicodec.Aes256, []byte{1, 2, 3})
		_, _, err := Resolver{}.Resolve(did.MustParseDID(didKey), nil)
		require.EqualError(t, err, "did:key: unsupported public key type: 0xa2")
	})
	t.Run("verify created DID document", func(t *testing.T) {
		const expected = `
{
  "@context": [
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
    "https://www.w3.org/ns/did/v1"
  ],
  "assertionMethod": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "authentication": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "capabilityDelegation": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "capabilityInvocation": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "keyAgreement": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "verificationMethod": [
    {
      "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "publicKeyJwk": {
        "crv": "Ed25519",
        "kty": "OKP",
        "x": "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY"
      },
      "type": "JsonWebKey2020"
    }
  ]
}
`
		doc, md, err := Resolver{}.Resolve(did.MustParseDID("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"), nil)
		require.NoError(t, err)
		require.NotNil(t, doc)
		require.NotNil(t, md)
		docJSON, _ := doc.MarshalJSON()
		assert.JSONEq(t, expected, string(docJSON))
		// Test the public key
		publicKey, err := doc.VerificationMethod[0].PublicKey()
		require.NoError(t, err)
		require.IsType(t, ed25519.PublicKey{}, publicKey)
	})
}

func TestNewResolver(t *testing.T) {
	assert.NotNil(t, NewResolver())
}

func createDIDKey(keyType multicodec.Code, data []byte) string {
	mcBytes := append(binary.AppendUvarint([]byte{}, uint64(keyType)), data...)
	return "did:key:z" + string(base58.EncodeAlphabet(mcBytes, base58.BTCAlphabet))
}

func TestRoundTrip(t *testing.T) {
	t.Run("secp384", func(t *testing.T) {
		keyPair, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		data := elliptic.MarshalCompressed(elliptic.P384(), keyPair.PublicKey.X, keyPair.PublicKey.Y)
		key := createDIDKey(multicodec.P384Pub, data)
		_, _, err := Resolver{}.Resolve(did.MustParseDID(key), nil)
		require.NoError(t, err)
	})
}
