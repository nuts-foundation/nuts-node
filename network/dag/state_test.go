/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

func TestNewState(t *testing.T) {
	t.Run("error creating DB files", func(t *testing.T) {
		_, err := NewState("state_test.go")

		assert.EqualError(t, err, "unable to create BBolt database: mkdir state_test.go: not a directory")
	})
}

func TestState_relayingFuncs(t *testing.T) {
	ctx := context.Background()
	txState := createState(t)
	tx, _, _ := CreateTestTransaction(1)
	payload := []byte{0, 0, 0, 1}
	txState.Add(ctx, tx, payload)
	payloadHash := hash.SHA256Sum(payload)

	t.Run("GetByPayloadHash", func(t *testing.T) {
		txs, err := txState.GetByPayloadHash(ctx, payloadHash)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, tx, txs[0])
	})

	t.Run("GetTransaction", func(t *testing.T) {
		txResult, err := txState.GetTransaction(ctx, tx.Ref())

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, tx, txResult)
		assert.Equal(t, uint32(0), txResult.Clock())
	})

	t.Run("IsPayloadPresent", func(t *testing.T) {
		result, err := txState.IsPayloadPresent(ctx, payloadHash)

		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, result)
	})

	t.Run("IsPresent", func(t *testing.T) {
		result, err := txState.IsPresent(ctx, tx.Ref())

		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, result)
	})

	t.Run("PayloadHashes", func(t *testing.T) {
		var result hash.SHA256Hash
		err := txState.PayloadHashes(ctx, func(payloadHash hash.SHA256Hash) error {
			result = payloadHash
			return nil
		})

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, payloadHash, result)
	})

	t.Run("ReadManyPayloads", func(t *testing.T) {
		var result bool
		var err error
		err = txState.ReadManyPayloads(ctx, func(ctx context.Context, reader PayloadReader) error {
			result, err = reader.IsPayloadPresent(ctx, payloadHash)
			return err
		})

		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, result)
	})

	t.Run("ReadPayload", func(t *testing.T) {
		result, err := txState.ReadPayload(ctx, payloadHash)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, payload, result)
	})
}

func TestState_Shutdown(t *testing.T) {
	txState := createState(t).(*state)

	err := txState.Shutdown()

	if !assert.NoError(t, err) {
		return
	}
	assert.Nil(t, txState.db)
}

func TestState_Start(t *testing.T) {
	t.Run("error - verifier failed", func(t *testing.T) {
		ctx := context.Background()
		txState := createState(t, func(_ context.Context, _ Transaction, _ State) error {
			return errors.New("failed")
		})
		tx := CreateTestTransactionWithJWK(0)

		err := txState.Add(ctx, tx, nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "transaction verification failed")
		present, err := txState.IsPresent(ctx, tx.Ref())
		assert.NoError(t, err)
		assert.False(t, present)
	})
}

func TestState_Observe(t *testing.T) {
	t.Run("transaction added", func(t *testing.T) {
		ctx := context.Background()
		txState := createState(t)
		var actual Transaction
		txState.RegisterObserver(func(ctx context.Context, transaction Transaction, _ []byte) {
			actual = transaction
		})
		expected := CreateTestTransactionWithJWK(1)

		err := txState.Add(ctx, expected, nil)

		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("transaction added with payload", func(t *testing.T) {
		ctx := context.Background()
		txState := createState(t)
		var actualTX Transaction
		var actualPayload []byte
		txState.RegisterObserver(func(ctx context.Context, transaction Transaction, payload []byte) {
			actualTX = transaction
			actualPayload = payload
		})
		expected := CreateTestTransactionWithJWK(1)

		err := txState.Add(ctx, expected, []byte{1})

		assert.NoError(t, err)
		assert.Equal(t, expected, actualTX)
		assert.Equal(t, []byte{1}, actualPayload)
	})
	t.Run("payload added", func(t *testing.T) {
		ctx := context.Background()
		txState := createState(t)
		var actual []byte
		txState.RegisterObserver(func(ctx context.Context, _ Transaction, payload []byte) {
			actual = payload
		})
		expected := []byte{1}

		err := txState.WritePayload(ctx, hash.EmptyHash(), expected)

		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
}

func TestState_Add(t *testing.T) {
	t.Run("error for transaction verification failure", func(t *testing.T) {
		ctx := context.Background()
		txState := createState(t, func(ctx context.Context, tx Transaction, state State) error {
			return errors.New("verification failed")
		})
		_ = txState.Start()

		err := txState.Add(ctx, transaction{}, nil)

		assert.Error(t, err)
	})
}

func TestState_Diagnostics(t *testing.T) {
	ctx := context.Background()
	txState := createState(t)
	doc1 := CreateTestTransactionWithJWK(2)
	txState.Add(ctx, doc1, nil)
	diagnostics := txState.Diagnostics()
	assert.Len(t, diagnostics, 3)
	// Assert actual diagnostics
	lines := make([]string, 0)
	for _, diagnostic := range diagnostics {
		lines = append(lines, diagnostic.Name()+": "+diagnostic.String())
	}
	sort.Strings(lines)

	dbSize := txState.Statistics(context.Background())
	assert.NotZero(t, dbSize)

	actual := strings.Join(lines, "\n")
	expected := fmt.Sprintf(`dag_heads: [`+doc1.Ref().String()+`]
dag_stored_database_size_bytes: %d
dag_transaction_count: 1`, dbSize.DataSize)
	assert.Equal(t, expected, actual)
}

func createState(t *testing.T, verifier ...Verifier) State {
	testDir := io.TestDirectory(t)
	s, _ := NewState(testDir, verifier...)
	t.Cleanup(func() {
		s.Shutdown()
	})
	return s
}
