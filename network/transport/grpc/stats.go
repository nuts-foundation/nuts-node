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

package grpc

import (
	"fmt"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"sort"
	"strings"
)

// numberOfPeersStatistic contains node's number of peers it's connected to.
type numberOfPeersStatistic struct {
	numberOfPeers int
}

func (n numberOfPeersStatistic) Result() interface{} {
	return n.numberOfPeers
}

// Name returns the name of the statistic.
func (n numberOfPeersStatistic) Name() string {
	return "connected_peers_count"
}

// String returns the statistic as string.
func (n numberOfPeersStatistic) String() string {
	return fmt.Sprintf("%d", n.numberOfPeers)
}

// peersStatistic contains the node's peers it's connected to.
type peersStatistic struct {
	peers []transport.Peer
}

func (p peersStatistic) Result() interface{} {
	return p.peers
}

// Name returns the name of the statistic.
func (p peersStatistic) Name() string {
	return "connected_peers"
}

// String returns the statistic as string.
func (p peersStatistic) String() string {
	addrs := make([]string, len(p.peers))
	for i, peer := range p.peers {
		addrs[i] = peer.String()
	}
	// Sort for stable order (easier for humans to understand)
	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i] > addrs[j]
	})
	return strings.Join(addrs, " ")
}

// ownPeerIDStatistic contains the node's own peer ID.
type ownPeerIDStatistic struct {
	peerID transport.PeerID
}

func (o ownPeerIDStatistic) Result() interface{} {
	return o.peerID
}

// Name returns the name of the statistic.
func (o ownPeerIDStatistic) Name() string {
	return "peer_id"
}

// String returns the statistic as string.
func (o ownPeerIDStatistic) String() string {
	return o.peerID.String()
}
