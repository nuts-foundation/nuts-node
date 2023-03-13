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

package dag

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	hash2 "github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
)

func TestNewTransaction(t *testing.T) {
	payloadHash, _ := hash2.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
	hash, _ := hash2.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")

	t.Run("ok", func(t *testing.T) {
		transaction, err := NewTransaction(payloadHash, "some/type", []hash2.SHA256Hash{hash}, nil, 1)

		require.NoError(t, err)
		assert.Equal(t, "some/type", transaction.PayloadType())
		assert.Equal(t, transaction.PayloadHash(), payloadHash)
		assert.Equal(t, []hash2.SHA256Hash{hash}, transaction.Previous())
		assert.Equal(t, Version(2), transaction.Version())
		assert.Equal(t, uint32(1), transaction.Clock())
	})
	t.Run("ok - with pal", func(t *testing.T) {
		transaction, err := NewTransaction(payloadHash, "some/type", []hash2.SHA256Hash{hash}, [][]byte{{1}, {2}}, 0)

		require.NoError(t, err)
		assert.Len(t, transaction.PAL(), 2)
	})
	t.Run("ok - with duplicates", func(t *testing.T) {
		transaction, err := NewTransaction(payloadHash, "some/type", []hash2.SHA256Hash{hash, hash}, nil, 0)

		require.NoError(t, err)
		assert.Equal(t, []hash2.SHA256Hash{hash}, transaction.Previous())
	})
	t.Run("error - type empty", func(t *testing.T) {
		transaction, err := NewTransaction(payloadHash, "", nil, nil, 0)
		assert.EqualError(t, err, errInvalidPayloadType.Error())
		assert.Nil(t, transaction)
	})
	t.Run("error - type not a MIME type", func(t *testing.T) {
		transaction, err := NewTransaction(payloadHash, "foo", nil, nil, 0)
		assert.EqualError(t, err, errInvalidPayloadType.Error())
		assert.Nil(t, transaction)
	})
	t.Run("error - invalid prev", func(t *testing.T) {
		transaction, err := NewTransaction(payloadHash, "foo/bar", []hash2.SHA256Hash{hash2.EmptyHash()}, nil, 0)
		assert.EqualError(t, err, errInvalidPrevs.Error())
		assert.Nil(t, transaction)
	})
}

func Test_transaction_Getters(t *testing.T) {
	payload, _ := hash2.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
	prev1, _ := hash2.ParseHex("3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986")
	prev2, _ := hash2.ParseHex("b3f2c3c396da1a949d214e4c2fe0fc9fb5f2a68ff1860df4ef10c9835e62e7c1")
	tx := transaction{
		prevs:       []hash2.SHA256Hash{prev1, prev2},
		payload:     payload,
		payloadType: "foo/bar",
		signingTime: time.Unix(1023323333, 0),
		version:     10,
	}
	tx.setData([]byte{1, 2, 3})

	assert.Equal(t, tx.prevs, tx.Previous())
	assert.Equal(t, tx.payload, tx.PayloadHash())
	assert.Equal(t, tx.payloadType, tx.PayloadType())
	assert.Equal(t, tx.signingTime, tx.SigningTime())
	assert.Equal(t, tx.version, tx.Version())
	assert.Equal(t, tx.data, tx.Data())
	assert.False(t, tx.Ref().Empty())
}

func Test_transaction_MarshalJSON(t *testing.T) {
	expected, _, _ := CreateTestTransaction(1)
	data, err := json.Marshal(expected)
	assert.NoError(t, err)
	assert.Equal(t, `"`+string(expected.Data())+`"`, string(data))
}

func generateKey() *ecdsa.PrivateKey {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key
}

func generateRSAKey() *rsa.PrivateKey {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	return key
}
