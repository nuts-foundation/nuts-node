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

package proto

import (
	"sync"
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/stretchr/testify/assert"
)

func TestPeerConsistencyHashStatistic(t *testing.T) {
	diagnostic := peerConsistencyHashStatistic{peerHashes: new(map[p2p.PeerID][]hash.SHA256Hash), mux: &sync.Mutex{}}
	diagnostic.copyFrom(map[p2p.PeerID][]hash.SHA256Hash{"abc": {hash.FromSlice([]byte{1, 2, 3})}})
	assert.Equal(t, diagnostic.String(), "0102030000000000000000000000000000000000000000000000000000000000={abc}")
}
