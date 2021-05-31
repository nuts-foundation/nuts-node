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
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"sort"
	"strings"
)

func newPeerOmnihashStatistic(input map[p2p.PeerID]hash.SHA256Hash) peerOmnihashStatistic {
	var inputCopy = make(map[p2p.PeerID]hash.SHA256Hash, len(input))
	for k, v := range input {
		inputCopy[k] = v.Clone()
	}
	return peerOmnihashStatistic{peerHashes: inputCopy}
}

type peerOmnihashStatistic struct {
	peerHashes map[p2p.PeerID]hash.SHA256Hash
}

func (d peerOmnihashStatistic) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.peerHashes)
}

func (d peerOmnihashStatistic) Name() string {
	return "Peer omnihashes"
}

func (d peerOmnihashStatistic) String() string {
	var groupedByHash = make(map[hash.SHA256Hash][]string)
	for peer, h := range d.peerHashes {
		groupedByHash[h] = append(groupedByHash[h], peer.String())
	}
	var items []string
	for h, peers := range groupedByHash {
		// Sort for stable order (easier for humans to understand)
		sort.Slice(peers, func(i, j int) bool {
			return peers[i] > peers[j]
		})
		items = append(items, fmt.Sprintf("%s={%s}", h, strings.Join(peers, ", ")))
	}
	// Sort for stable order (easier for humans to understand)
	sort.Slice(items, func(i, j int) bool {
		return items[i] > items[j]
	})
	return strings.Join(items, ", ")
}
