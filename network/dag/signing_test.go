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
	"crypto/sha1"
	"encoding/base32"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/stretchr/testify/require"

	"github.com/nuts-foundation/nuts-node/crypto"

	hash2 "github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
)

func TestTransactionSigner(t *testing.T) {
	payloadHash, _ := hash2.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
	key := generateKey()
	kidAsArray := sha1.Sum(key.X.Bytes())
	kid := base32.HexEncoding.EncodeToString(kidAsArray[:])
	prev1, _ := hash2.ParseHex("3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986")
	prev2, _ := hash2.ParseHex("b3f2c3c396da1a949d214e4c2fe0fc9fb5f2a68ff1860df4ef10c9835e62e7c1")
	expectedPrevs := []hash2.SHA256Hash{prev1, prev2}
	contentType := "foo/bar"
	moment := time.Date(2020, 10, 23, 13, 0, 0, 0, time.FixedZone("test", 1))
	jwxSigner := crypto.NewMemoryCryptoInstance()
	ctx := audit.TestContext()
	t.Run("ok - attach key", func(t *testing.T) {
		tx, err := NewTransaction(payloadHash, contentType, expectedPrevs, nil, 0)
		require.NoError(t, err)

		key := crypto.NewTestKey(kid)
		signedTx, err := NewTransactionSigner(jwxSigner, key, true).Sign(ctx, tx, moment)
		require.NoError(t, err)
		// JWS headers
		assert.Equal(t, contentType, signedTx.PayloadType())
		assert.Empty(t, signedTx.SigningKeyID())
		// Custom headers
		assert.Equal(t, "2020-10-23 12:59:59 +0000 UTC", signedTx.SigningTime().String())
		assert.Equal(t, Version(2), signedTx.Version())
		prevs := signedTx.Previous()
		assert.Len(t, prevs, 2, "expected 2 prevs")
		assert.Equal(t, prev1, prevs[0])
		assert.Equal(t, prev2, prevs[1])
		// Resulting tx
		assert.NotEmpty(t, signedTx.Data())
		assert.False(t, signedTx.Ref().Empty())
		assert.Equal(t, time.UTC, signedTx.SigningTime().Location())
	})
	t.Run("ok - with kid", func(t *testing.T) {
		tx, err := NewTransaction(payloadHash, contentType, expectedPrevs, nil, 0)
		require.NoError(t, err)

		key := crypto.NewTestKey(kid)
		signedTx, err := NewTransactionSigner(jwxSigner, key, false).Sign(ctx, tx, moment)
		require.NoError(t, err)
		assert.Equal(t, kid, signedTx.SigningKeyID())
		assert.Nil(t, signedTx.SigningKey())
		assert.NotEmpty(t, signedTx.Data())
	})
	t.Run("signing time is zero", func(t *testing.T) {
		tx, _ := NewTransaction(payloadHash, contentType, expectedPrevs, nil, 0)
		signedTransaction, err := NewTransactionSigner(jwxSigner, crypto.NewTestKey(kid), false).Sign(ctx, tx, time.Time{})
		assert.Empty(t, signedTransaction)
		assert.EqualError(t, err, "signing time is zero")
	})
	t.Run("already signed", func(t *testing.T) {
		tx, _ := NewTransaction(payloadHash, contentType, expectedPrevs, nil, 0)
		signer := NewTransactionSigner(jwxSigner, crypto.NewTestKey(kid), false)
		signedTransaction, _ := signer.Sign(ctx, tx, time.Now())
		signedTransaction2, err := signer.Sign(ctx, signedTransaction, time.Now())
		assert.Nil(t, signedTransaction2)
		assert.EqualError(t, err, "transaction is already signed")
	})
}
