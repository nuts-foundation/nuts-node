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
	"context"
	"crypto/ecdsa"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCrypto_Decrypt(t *testing.T) {
	ctx := context.Background()
	t.Run("ok", func(t *testing.T) {
		client := createCrypto(t)
		kid := "kid"
		key, _ := client.New(audit.TestContext(), ECP256Key, StringNamingFunc(kid))
		pubKey := key.Public().(*ecdsa.PublicKey)

		cipherText, err := EciesEncrypt(pubKey, []byte("hello!"))
		assert.NoError(t, err)

		plainText, err := client.Decrypt(ctx, "kid", cipherText)
		assert.NoError(t, err)

		assert.Equal(t, "hello!", string(plainText))
	})
	t.Run("error - invalid kid", func(t *testing.T) {
		client := createCrypto(t)

		_, err := client.Decrypt(ctx, "../ceritifcate", nil)

		assert.ErrorContains(t, err, "invalid key ID")
	})
}
