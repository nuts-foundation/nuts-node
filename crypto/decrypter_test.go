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
	"testing"

	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/stretchr/testify/assert"
)

func TestCrypto_Decrypt(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		client := createCrypto(t)
		kid := "kid"
		key, _ := client.New(audit.TestContext(), StringNamingFunc(kid))
		pubKey := key.Public().(*ecdsa.PublicKey)

		cipherText, err := EciesEncrypt(pubKey, []byte("hello!"))
		assert.NoError(t, err)

		plainText, err := client.Decrypt("kid", cipherText)
		assert.NoError(t, err)

		assert.Equal(t, "hello!", string(plainText))
	})
	t.Run("error - invalid kid", func(t *testing.T) {
		client := createCrypto(t)

		_, err := client.Decrypt("../ceritifcate", nil)

		assert.ErrorContains(t, err, "invalid key ID")
	})
}
