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
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

func TestBBoltPayloadStore_ReadWrite(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	ctx := context.Background()
	payloadStore := NewBBoltPayloadStore(createBBoltDB(testDirectory))

	payload := []byte("Hello, World!")
	hash := hash.SHA256Sum(payload)
	// Before, payload should not be present
	present, err := payloadStore.IsPresent(ctx, hash)
	if !assert.NoError(t, err) || !assert.False(t, present) {
		return
	}
	// Add payload
	err = payloadStore.WritePayload(ctx, hash, payload)
	if !assert.NoError(t, err) {
		return
	}
	// Now it should be present
	present, err = payloadStore.IsPresent(ctx, hash)
	if !assert.NoError(t, err) || !assert.True(t, present, "payload should be present") {
		return
	}
	// Read payload
	data, err := payloadStore.ReadPayload(ctx, hash)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, payload, data)
}

func TestBBoltPayloadStore_Observe(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	payloadStore := NewBBoltPayloadStore(createBBoltDB(testDirectory))
	ctx := context.Background()

	var actual interface{}
	payloadStore.RegisterObserver(func(_ context.Context, subject interface{}) {
		actual = subject
	})
	payload := []byte(t.Name())
	expected := hash.SHA256Sum(payload)
	err := payloadStore.WritePayload(ctx, expected, payload)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}
