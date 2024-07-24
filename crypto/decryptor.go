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

package crypto

import (
	"context"
	"crypto/ecdsa"
	"errors"
)

// Decrypt decrypts the `cipherText` with key `kid`
func (client *Crypto) Decrypt(ctx context.Context, kid string, cipherText []byte) ([]byte, error) {
	keyRef, err := findKeyReferenceByKid(ctx, client.db, kid)
	if err != nil {
		return nil, err
	}
	key, err := client.backend.GetPrivateKey(ctx, keyRef.KeyName, keyRef.Version)
	if err != nil {
		return nil, err
	}

	switch privateKey := key.(type) {
	case *ecdsa.PrivateKey:
		return EciesDecrypt(privateKey, cipherText)
	default:
		return nil, errors.New("unsupported decryption key")
	}
}
