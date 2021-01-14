/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"

	"github.com/mr-tron/base58"
)

// Fingerprint calculates the key fingerprint which is used as kid
// todo use jwk lib for fingerprint
func Fingerprint(publicKey ecdsa.PublicKey) string {
	// calculate kid as BASE-58(SHA-256(raw-public-key-bytes))
	keyBytes := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)
	sha := sha256.Sum256(keyBytes)

	return base58.Encode(sha[:])
}
