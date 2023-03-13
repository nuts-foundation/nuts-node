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
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/test/io"
)

func TestPayloadStore_ReadWrite(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	db := createBBoltDB(testDirectory)
	payloadStore := NewPayloadStore().(*payloadStore)

	err := db.Write(context.Background(), func(tx stoabs.WriteTx) error {
		payload := []byte("Hello, World!")
		hash := hash.SHA256Sum(payload)
		// Before, payload should not be present
		present := payloadStore.isPayloadPresent(tx, hash)
		if !assert.False(t, present) {
			return nil
		}
		// Add payload
		err := payloadStore.writePayload(tx, hash, payload)
		require.NoError(t, err)
		// Now it should be present
		present = payloadStore.isPayloadPresent(tx, hash)
		if !assert.True(t, present, "payload should be present") {
			return nil
		}
		// Read payload
		data, err := payloadStore.readPayload(tx, hash)
		assert.NoError(t, err)
		assert.Equal(t, payload, data)
		return nil
	})
	assert.NoError(t, err)
}

func TestPayloadStore_readPayload(t *testing.T) {
	ctrl := gomock.NewController(t)
	tx := stoabs.NewMockReadTx(ctrl)
	reader := stoabs.NewMockReader(ctrl)
	payloadStore := NewPayloadStore().(*payloadStore)

	t.Run("error - read failure", func(t *testing.T) {
		h := hash.FromSlice([]byte("test read"))
		tx.EXPECT().GetShelfReader(payloadsShelf).Return(reader)
		reader.EXPECT().Get(gomock.Any()).Return([]byte("not nil"), errors.New("custom"))

		data, err := payloadStore.readPayload(tx, h)

		assert.Nil(t, data)
		assert.EqualError(t, err, fmt.Sprintf("failed to read payload (hash=%s): custom", h))
	})
}

func TestPayloadStore_writePayload(t *testing.T) {
	ctrl := gomock.NewController(t)
	tx := stoabs.NewMockWriteTx(ctrl)
	writer := stoabs.NewMockWriter(ctrl)
	payloadStore := NewPayloadStore().(*payloadStore)

	t.Run("error - write failure", func(t *testing.T) {
		h := hash.FromSlice([]byte("test write"))
		tx.EXPECT().GetShelfWriter(payloadsShelf).Return(writer)
		writer.EXPECT().Put(gomock.Any(), gomock.Any()).Return(errors.New("custom"))

		err := payloadStore.writePayload(tx, h, nil)

		assert.EqualError(t, err, "custom")
	})
}
func TestPayloadStore_isPresent(t *testing.T) {
	ctrl := gomock.NewController(t)
	tx := stoabs.NewMockReadTx(ctrl)
	payloadStore := NewPayloadStore().(*payloadStore)
	reader := stoabs.NewMockReader(ctrl)

	t.Run("error - readPayload failure", func(t *testing.T) {
		h := hash.FromSlice([]byte("test isPresent"))
		tx.EXPECT().GetShelfReader(payloadsShelf).Return(reader)
		reader.EXPECT().Get(stoabs.NewHashKey(h)).Return(nil, errors.New("error"))

		present := payloadStore.isPayloadPresent(tx, h)

		assert.False(t, present)
	})
}
