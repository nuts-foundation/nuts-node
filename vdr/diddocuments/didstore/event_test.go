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
 */

package didstore

import (
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var sha0s = mustParseHash("0000000000000000000000000000000000000000000000000000000000000000")
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

func TestEventList_Add(t *testing.T) {
	el := eventList{}

	el.insert(event{})

	assert.Len(t, el.Events, 1)
}

func TestEventList_Sort(t *testing.T) {
	t.Run("in order", func(t *testing.T) {
		el := eventList{}

		el.insert(event{TXRef: sha0s})
		el.insert(event{TXRef: sha1s, LogicalClock: 1})

		require.Len(t, el.Events, 2)
		assert.Equal(t, sha0s, el.Events[0].TXRef)
		assert.Equal(t, sha1s, el.Events[1].TXRef)
	})

	t.Run("in reverse", func(t *testing.T) {
		el := eventList{}

		el.insert(event{TXRef: sha1s, LogicalClock: 1})
		el.insert(event{TXRef: sha0s})

		require.Len(t, el.Events, 2)
		assert.Equal(t, sha0s, el.Events[0].TXRef)
		assert.Equal(t, sha1s, el.Events[1].TXRef)
	})

	t.Run("conflict in order", func(t *testing.T) {
		el := eventList{}

		el.insert(event{TXRef: sha0s})
		el.insert(event{TXRef: sha1s, LogicalClock: 1})
		el.insert(event{TXRef: sha2s, LogicalClock: 1, Created: time.Now()})

		require.Len(t, el.Events, 3)
		assert.Equal(t, sha0s, el.Events[0].TXRef)
		assert.Equal(t, sha1s, el.Events[1].TXRef)
		assert.Equal(t, sha2s, el.Events[2].TXRef)
	})

	t.Run("conflict out of order", func(t *testing.T) {
		el := eventList{}

		el.insert(event{TXRef: sha2s, LogicalClock: 1, Created: time.Now()})
		el.insert(event{TXRef: sha0s})
		el.insert(event{TXRef: sha1s, LogicalClock: 1})

		require.Len(t, el.Events, 3)
		assert.Equal(t, sha0s, el.Events[0].TXRef)
		assert.Equal(t, sha1s, el.Events[1].TXRef)
		assert.Equal(t, sha2s, el.Events[2].TXRef)
	})
}

func TestEventList_updates(t *testing.T) {
	t.Run("empty lists", func(t *testing.T) {
		el := eventList{}

		common, list := el.updates(el)

		assert.Nil(t, common)
		assert.Equal(t, 0, len(list))
	})

	t.Run("first update", func(t *testing.T) {
		from := eventList{}
		to := eventList{}
		to.insert(event{TXRef: sha0s})

		common, list := from.updates(to)

		assert.Nil(t, common)
		assert.Equal(t, 1, len(list))
	})

	t.Run("start with conflict", func(t *testing.T) {
		from := eventList{}
		to := eventList{}
		from.insert(event{TXRef: sha1s})
		to.insert(event{TXRef: sha0s})

		common, list := from.updates(to)

		assert.Nil(t, common)
		assert.Equal(t, 2, len(list))
	})

	t.Run("insert at end", func(t *testing.T) {
		from := eventList{}
		to := eventList{}
		from.insert(event{TXRef: sha0s})
		to.insert(event{TXRef: sha0s})
		to.insert(event{TXRef: sha1s, LogicalClock: 1})

		common, list := from.updates(to)

		assert.Equal(t, event{TXRef: sha0s}, *common)
		require.Len(t, list, 1)
		assert.Equal(t, event{TXRef: sha1s, LogicalClock: 1}, list[0])
	})

	t.Run("correctly ordered", func(t *testing.T) {
		from := eventList{}
		to := eventList{}
		created := time.Now()
		from.insert(event{TXRef: sha0s})
		from.insert(event{TXRef: sha1s, LogicalClock: 1, Created: created})
		to.insert(event{TXRef: sha0s})
		to.insert(event{TXRef: sha2s, LogicalClock: 1})
		to.insert(event{TXRef: sha3s, LogicalClock: 2})

		common, list := from.updates(to)

		assert.Equal(t, event{TXRef: sha0s}, *common)
		require.Len(t, list, 3)
		assert.Equal(t, event{TXRef: sha2s, LogicalClock: 1}, list[0])
		assert.Equal(t, event{TXRef: sha1s, LogicalClock: 1, Created: created}, list[1])
		assert.Equal(t, event{TXRef: sha3s, LogicalClock: 2}, list[2])
	})
}

func TestEventList_copy(t *testing.T) {
	el := eventList{}
	cp := el.copy()

	el.insert(event{TXRef: sha0s})

	assert.Equal(t, 0, len(cp.Events))

}
