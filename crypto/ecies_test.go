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
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	ecies "github.com/nuts-foundation/crypto-ecies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestEciesEncryptDecrypt_SmallestPlaintext backs the claim in validateEciesCiphertextLength's
// godoc that the shortest ciphertext ecies.Encrypt can ever legitimately produce (114 bytes, for a
// 1-byte P-256 plaintext) is already 1 byte above that function's 113-byte reject threshold, so
// the length check never rejects honestly encrypted data.
func TestEciesEncryptDecrypt_SmallestPlaintext(t *testing.T) {
	key, err := generateECKeyPair()
	require.NoError(t, err)

	cipherText, err := EciesEncrypt(&key.PublicKey, []byte{0x01})
	require.NoError(t, err)
	require.Len(t, cipherText, 114)

	plainText, err := EciesDecrypt(key, cipherText)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x01}, plainText)
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

// TestEciesDecrypt_ShortCiphertext checks the length boundary on its own: too-short input is
// rejected uniformly regardless of content, since the length check runs before anything is parsed
// as an EC point or MAC. It doesn't by itself prove the original panic is gone, because
// ecies.PrivateKey.Decrypt rejects non-point garbage (ErrInvalidPublicKey) before it would ever
// reach the vulnerable code; see TestEciesDecrypt_ForgedShortCiphertext for that.
func TestEciesDecrypt_ShortCiphertext(t *testing.T) {
	key, err := generateECKeyPair()
	require.NoError(t, err)

	t.Run("below the corrected minimum (rLen+hLen+BlockSize=113 for P-256) is rejected", func(t *testing.T) {
		for _, length := range []int{0, 1, 10, 97, 98, 100, 112} {
			t.Run(fmt.Sprintf("%d bytes", length), func(t *testing.T) {
				cipherText := make([]byte, length)
				if length > 0 {
					cipherText[0] = 4 // ecies.PrivateKey.Decrypt only proceeds past its own check for prefix 2, 3 or 4
				}

				plainText, err := EciesDecrypt(key, cipherText)

				assert.ErrorIs(t, err, ecies.ErrInvalidMessage)
				assert.Nil(t, plainText)
			})
		}
	})
	t.Run("at the corrected minimum length, decryption is attempted (and fails cleanly on garbage input)", func(t *testing.T) {
		cipherText := make([]byte, 113)
		cipherText[0] = 4

		plainText, err := EciesDecrypt(key, cipherText)

		assert.Error(t, err)
		assert.Nil(t, plainText)
	})
}

// TestEciesDecrypt_ForgedShortCiphertext reproduces the actual attack from the issue this fixes:
// a genuine ephemeral key and a correctly-computed MAC (the attacker only needs the victim's
// public key for both, which is published in its DID document) wrapped around a 1-byte body,
// assembled into a 98-byte ciphertext. Before the fix, ecies.PrivateKey.Decrypt's own length check
// (rLen+hLen+1 = 98 bytes) let this through, and symDecrypt then computed
// make([]byte, len(ct)-BlockSize) with len(ct)=1, panicking. EciesEncrypt can't produce this
// shape itself -- symEncrypt always pads to at least one full block (16 bytes) -- so this has to
// be forged by hand, replicating ecies.PrivateKey.Decrypt's own key derivation and tagging
// (deriveKeys/messageTag) exactly, since those aren't exported.
func TestEciesDecrypt_ForgedShortCiphertext(t *testing.T) {
	victim, err := generateECKeyPair()
	require.NoError(t, err)

	ephemeral, err := ecies.GenerateKey(rand.Reader, elliptic.P256(), ecies.ECIES_AES128_SHA256)
	require.NoError(t, err)

	z, err := ephemeral.GenerateShared(ecies.ImportECDSAPublic(&victim.PublicKey), 16, 16)
	require.NoError(t, err)
	_, km := deriveKeysForTest(z, 16)

	body := []byte{0x42} // 1-byte body, as in the issue's PoC
	tag := hmac.New(sha256.New, km)
	tag.Write(body)
	mac := tag.Sum(nil)

	r := elliptic.Marshal(elliptic.P256(), ephemeral.PublicKey.X, ephemeral.PublicKey.Y) // 65 bytes
	cipherText := append(append(append([]byte{}, r...), body...), mac...)
	require.Len(t, cipherText, 98) // matches the issue's PoC exactly

	plainText, err := EciesDecrypt(victim, cipherText)

	assert.ErrorIs(t, err, ecies.ErrInvalidMessage)
	assert.Nil(t, plainText)
}

// deriveKeysForTest replicates ecies.deriveKeys (NIST SP 800-56 concatenation KDF followed by a
// hash over Km), which isn't exported. s1 is nil, matching how decryptPAL calls EciesDecrypt.
func deriveKeysForTest(z []byte, keyLen int) (ke, km []byte) {
	h := sha256.New()
	counter := uint32(1)
	var k []byte
	for len(k) < 2*keyLen {
		var counterBytes [4]byte
		binary.BigEndian.PutUint32(counterBytes[:], counter)
		h.Reset()
		h.Write(counterBytes[:])
		h.Write(z)
		k = h.Sum(k)
		counter++
	}
	k = k[:2*keyLen]
	ke = k[:keyLen]
	km = k[keyLen:]
	h.Reset()
	h.Write(km)
	km = h.Sum(nil)
	return ke, km
}
