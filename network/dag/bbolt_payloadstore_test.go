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
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"go.etcd.io/bbolt"
)

func TestBBoltPayloadStore_ReadWrite(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	db := createBBoltDB(testDirectory)
	payloadStore := NewBBoltPayloadStore(db)

	db.Update(func(tx *bbolt.Tx) error {
		payload := []byte("Hello, World!")
		hash := hash.SHA256Sum(payload)
		// Before, payload should not be present
		present := payloadStore.isPayloadPresent(tx, hash)
		if !assert.False(t, present) {
			return nil
		}
		// Add payload
		err := payloadStore.writePayload(tx, hash, payload)
		if !assert.NoError(t, err) {
			return nil
		}
		// Now it should be present
		present = payloadStore.isPayloadPresent(tx, hash)
		if !assert.True(t, present, "payload should be present") {
			return nil
		}
		// Read payload
		data := payloadStore.readPayload(tx, hash)
		assert.Equal(t, payload, data)
		return nil
	})
}
