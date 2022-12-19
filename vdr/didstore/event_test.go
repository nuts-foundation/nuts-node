/*
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

package didstore

import (
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var sha0s = mustParseHash("0000000000000000000000000000000000000000000000000000000000000001")
var sha1s = mustParseHash("1111111111111111111111111111111111111111111111111111111111111111")
var sha2s = mustParseHash("2222222222222222222222222222222222222222222222222222222222222222")
var sha3s = mustParseHash("3333333333333333333333333333333333333333333333333333333333333333")

func mustParseHash(hex string) hash.SHA256Hash {
	h, err := hash.ParseHex(hex)
	if err != nil {
		panic(err)
	}
	return h
}

func TestEventList_insert(t *testing.T) {
	el := eventList{}

	el.insert(event{})

	assert.Len(t, el.Events, 1)
}

func TestEventList_Insert(t *testing.T) {
	t.Run("in order", func(t *testing.T) {
		el := eventList{}

		assert.Equal(t, 0, el.insert(event{TXRef: sha0s}))
		assert.Equal(t, 1, el.insert(event{TXRef: sha1s, Clock: 1}))

		require.Len(t, el.Events, 2)
		assert.Equal(t, sha0s, el.Events[0].TXRef)
		assert.Equal(t, sha1s, el.Events[1].TXRef)
	})

	t.Run("in reverse", func(t *testing.T) {
		el := eventList{}

		assert.Equal(t, 0, el.insert(event{TXRef: sha1s, Clock: 1}))
		assert.Equal(t, 0, el.insert(event{TXRef: sha0s}))

		require.Len(t, el.Events, 2)
		assert.Equal(t, sha0s, el.Events[0].TXRef)
		assert.Equal(t, sha1s, el.Events[1].TXRef)
	})

	t.Run("conflict in order", func(t *testing.T) {
		el := eventList{}

		assert.Equal(t, 0, el.insert(event{TXRef: sha0s}))
		assert.Equal(t, 1, el.insert(event{TXRef: sha1s, Clock: 1}))
		assert.Equal(t, 2, el.insert(event{TXRef: sha2s, Clock: 1, Created: time.Now()}))

		require.Len(t, el.Events, 3)
		assert.Equal(t, sha0s, el.Events[0].TXRef)
		assert.Equal(t, sha1s, el.Events[1].TXRef)
		assert.Equal(t, sha2s, el.Events[2].TXRef)
	})

	t.Run("conflict out of order", func(t *testing.T) {
		el := eventList{}

		assert.Equal(t, 0, el.insert(event{TXRef: sha2s, Clock: 1, Created: time.Now()}))
		assert.Equal(t, 0, el.insert(event{TXRef: sha0s}))
		assert.Equal(t, 1, el.insert(event{TXRef: sha1s, Clock: 1}))

		require.Len(t, el.Events, 3)
		assert.Equal(t, sha0s, el.Events[0].TXRef)
		assert.Equal(t, sha1s, el.Events[1].TXRef)
		assert.Equal(t, sha2s, el.Events[2].TXRef)
	})
}
