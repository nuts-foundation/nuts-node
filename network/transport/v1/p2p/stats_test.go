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

package p2p

import (
	"github.com/magiconair/properties/assert"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"testing"
)

func Test_NumberOfPeersStatistic(t *testing.T) {
	statistic := numberOfPeersStatistic{numberOfPeers: 10}
	assert.Equal(t, statistic.String(), "10")
	assert.Equal(t, statistic.Name(), "[P2P Network] Connected peers #")
}

func Test_PeersStatistic(t *testing.T) {
	statistic := peersStatistic{peers: []transport.Peer{
		{ID: "abc", Address: "localhost:8080"},
		{ID: "def", Address: "remote:8081"},
	}}
	assert.Equal(t, statistic.String(), "def@remote:8081 abc@localhost:8080")
	assert.Equal(t, statistic.Name(), "[P2P Network] Connected peers")
}

func Test_OwnPeerIDStatistic(t *testing.T) {
	statistic := ownPeerIDStatistic{peerID: "bla"}
	assert.Equal(t, statistic.String(), "bla")
	assert.Equal(t, statistic.Name(), "[P2P Network] Peer ID of local node")
}
