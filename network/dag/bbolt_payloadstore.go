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
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// payloadsBucketName is the name of the Bolt bucket that holds the payloads of the transactions.
const payloadsBucketName = "payloads"

// NewBBoltPayloadStore creates a etcd/bbolt backed payload store using the given database.
func NewBBoltPayloadStore(db stoabs.KVStore) PayloadStore {
	return &bboltPayloadStore{db: db}
}

type bboltPayloadStore struct {
	db stoabs.KVStore
}

func (store bboltPayloadStore) isPayloadPresent(tx stoabs.ReadTx, payloadHash hash.SHA256Hash) bool {
	reader, _ := tx.GetShelfReader(payloadsBucketName)
	if reader == nil {
		return false
	}
	data, _ := reader.Get(stoabs.BytesKey(payloadHash.Slice()))
	return len(data) > 0
}

func (store bboltPayloadStore) readPayload(tx stoabs.ReadTx, payloadHash hash.SHA256Hash) []byte {
	reader, _ := tx.GetShelfReader(payloadsBucketName)
	if reader == nil {
		return nil
	}
	data, _ := reader.Get(stoabs.BytesKey(payloadHash.Slice()))
	return data
}

func (store bboltPayloadStore) writePayload(tx stoabs.WriteTx, payloadHash hash.SHA256Hash, data []byte) error {
	payloads, err := tx.GetShelfWriter(payloadsBucketName)
	if err != nil {
		return err
	}
	return payloads.Put(stoabs.BytesKey(payloadHash.Slice()), data)
}
