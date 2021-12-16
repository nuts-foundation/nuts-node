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
	key := ecies.ImportECDSA(privateKey)

	return key.Decrypt(cipherText, nil, nil)
}

// EciesEncrypt encrypts the `plainText` using the Elliptic Curve Integrated Encryption Scheme
func EciesEncrypt(publicKey *ecdsa.PublicKey, plainText []byte) ([]byte, error) {
	key := ecies.ImportECDSAPublic(publicKey)

	return ecies.Encrypt(rand.Reader, key, plainText, nil, nil)
}
