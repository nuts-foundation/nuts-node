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

type NumberOfPeersStatistic struct {
	NumberOfPeers int
}

func (n NumberOfPeersStatistic) Name() string {
	return "[P2P Network] Connected peers #"
}

func (n NumberOfPeersStatistic) String() string {
	return fmt.Sprintf("%d", n.NumberOfPeers)
}

type PeersStatistic struct {
	Peers []Peer
}

func (p PeersStatistic) Name() string {
	return "[P2P Network] Connected peers"
}

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

type OwnPeerIDStatistic struct {
	peerID PeerID
}

func (o OwnPeerIDStatistic) Name() string {
	return "[P2P Network] Peer ID of local node"
}

func (o OwnPeerIDStatistic) String() string {
	return o.peerID.String()
}

