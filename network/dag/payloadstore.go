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
	"errors"
	"fmt"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
)

// payloadsShelf is the name of the shelf that holds the payloads of the transactions.
const payloadsShelf = "payloads"

// NewPayloadStore creates a new payload store.
func NewPayloadStore() PayloadStore {
	return &payloadStore{}
}

type payloadStore struct{}

func (store payloadStore) isPayloadPresent(tx stoabs.ReadTx, payloadHash hash.SHA256Hash) bool {
	data, err := store.readPayload(tx, payloadHash)
	if err != nil {
		if !errors.Is(err, ErrPayloadNotFound) {
			log.Logger().
				WithError(err).
				Error("Failed to verify payload existence")
		}
		return false
	}
	return len(data) > 0
}

func (store payloadStore) readPayload(tx stoabs.ReadTx, payloadHash hash.SHA256Hash) ([]byte, error) {
	reader := tx.GetShelfReader(payloadsShelf)
	data, err := reader.Get(stoabs.NewHashKey(payloadHash))
	if errors.Is(err, stoabs.ErrKeyNotFound) {
		return nil, ErrPayloadNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read payload (hash=%s): %w", payloadHash, err)
	}
	return data, nil
}

func (store payloadStore) writePayload(tx stoabs.WriteTx, payloadHash hash.SHA256Hash, data []byte) error {
	writer := tx.GetShelfWriter(payloadsShelf)
	return writer.Put(stoabs.NewHashKey(payloadHash), data)
}
