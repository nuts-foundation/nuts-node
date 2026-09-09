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
	"crypto/rand"

	ecies "github.com/nuts-foundation/crypto-ecies"
)

// EciesDecrypt decrypts the `cipherText` using the Elliptic Curve Integrated Encryption Scheme
func EciesDecrypt(privateKey *ecdsa.PrivateKey, cipherText []byte) ([]byte, error) {
	if err := validateEciesCiphertextLength(privateKey, cipherText); err != nil {
		return nil, err
	}

	key := ecies.ImportECDSA(privateKey)

	return key.Decrypt(cipherText, nil, nil)
}

// validateEciesCiphertextLength rejects a ciphertext too short to decrypt without
// ecies.PrivateKey.Decrypt computing a negative slice length and panicking. That function accepts
// anything of at least rLen+hLen+1 bytes (the ephemeral public key plus the MAC plus one byte),
// but then hands the rLen+hLen bytes after that to symDecrypt, which subtracts a full cipher block
// size from their length before allocating - anything short of rLen+hLen+BlockSize underflows.
// rLen, hLen and BlockSize are reproduced here exactly as ecies.PrivateKey.Decrypt computes them
// (see its source, ecies.go, and the params it looks up in params.go), using the same per-curve
// parameter lookup, so this covers every curve the library supports, not just P-256.
//
// For P-256 (what this codebase actually uses): rLen=65 (uncompressed EC point), hLen=32 (SHA-256),
// BlockSize=16 (AES), so this rejects anything under 113 bytes. That's below what honestly
// encrypted data ever produces: ecies.Encrypt pads the body to at least one cipher block, and
// additionally refuses to encrypt a plaintext that would produce a body of exactly one block
// (len(em) <= BlockSize check in Encrypt), so the smallest real ciphertext is for a 1-byte
// plaintext at rLen+hLen+(BlockSize+1) = 114 bytes - one byte above this floor. Verified
// empirically (encrypt/decrypt round-trip for 0/1/2/5-byte plaintexts against a fresh P-256 key):
// 0 bytes -> Encrypt returns (nil, nil) (pre-existing library behaviour, unrelated to this
// change), 1 byte -> 114-byte ciphertext, round-trips; 2 bytes -> 115; 5 bytes -> 118. So this
// check never rejects anything the library's own Encrypt can produce - only ciphertext that was
// never honestly encrypted, exactly the attacker-forged case this closes.
func validateEciesCiphertextLength(privateKey *ecdsa.PrivateKey, cipherText []byte) error {
	curve := privateKey.PublicKey.Curve
	params := ecies.ParamsFromCurve(curve)
	if params == nil {
		return ecies.ErrUnsupportedECIESParameters
	}
	// rLen is copied verbatim from ecies.PrivateKey.Decrypt (see ecies.go in the crypto-ecies
	// module), not re-derived here: this check only works because it predicts exactly what that
	// function is about to compute. A "more correct" version of this formula could disagree with
	// the library's own arithmetic on some curve and let something through - or reject something
	// valid - so it has to match, not just be equivalent.
	rLen := (curve.Params().BitSize + 7) / 4
	hLen := params.Hash().Size()
	if len(cipherText) < rLen+hLen+params.BlockSize {
		return ecies.ErrInvalidMessage
	}
	return nil
}

// EciesEncrypt encrypts the `plainText` using the Elliptic Curve Integrated Encryption Scheme
func EciesEncrypt(publicKey *ecdsa.PublicKey, plainText []byte) ([]byte, error) {
	key := ecies.ImportECDSAPublic(publicKey)

	return ecies.Encrypt(rand.Reader, key, plainText, nil, nil)
}
