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
	"fmt"
	"sort"
	"strings"
)

// NumberOfPeersStatistic contains node's number of peers it's connected to.
type NumberOfPeersStatistic struct {
	NumberOfPeers int
}

// Name returns the name of the statistic.
func (n NumberOfPeersStatistic) Name() string {
	return "[P2P Network] Connected peers #"
}

// String returns the statistic as string.
func (n NumberOfPeersStatistic) String() string {
	return fmt.Sprintf("%d", n.NumberOfPeers)
}

// PeersStatistic contains the node's peers it's connected to.
type PeersStatistic struct {
	Peers []Peer
}

// Name returns the name of the statistic.
func (p PeersStatistic) Name() string {
	return "[P2P Network] Connected peers"
}

// String returns the statistic as string.
func (p PeersStatistic) String() string {
	addrs := make([]string, len(p.Peers))
	for i, peer := range p.Peers {
		addrs[i] = peer.String()
	}
	// Sort for stable order (easier for humans to understand)
	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i] > addrs[j]
	})
	return strings.Join(addrs, " ")
}

// OwnPeerIDStatistic contains the node's own peer ID.
type OwnPeerIDStatistic struct {
	peerID PeerID
}

// Name returns the name of the statistic.
func (o OwnPeerIDStatistic) Name() string {
	return "[P2P Network] Peer ID of local node"
}

// String returns the statistic as string.
func (o OwnPeerIDStatistic) String() string {
	return o.peerID.String()
}
