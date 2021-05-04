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
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	log "github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/p2p"
)

// protocol is thread-safe when callers use the Protocol interface
type protocol struct {
	p2pNetwork   p2p.Adapter
	graph        dag.DAG
	payloadStore dag.PayloadStore
	sender       messageSender
	// TODO: What if no-one is actually listening to this queue? Maybe we should create it when someone asks for it (lazy initialization)?
	receivedPeerHashes        *chanPeerHashQueue
	receivedTransactionHashes *chanPeerHashQueue

	peerOmnihashChannel chan PeerOmnihash
	// peerOmnihashes contains the omnihashes of our peers. Access must be protected using peerOmnihashMutex
	peerOmnihashes    map[p2p.PeerID]hash.SHA256Hash
	peerOmnihashMutex *sync.Mutex

	blocks dagBlocks

	advertHashesInterval time.Duration
	// peerID contains our own peer ID which can be logged for debugging purposes
	peerID p2p.PeerID
}

func (p *protocol) Diagnostics() []core.DiagnosticResult {
	p.peerOmnihashMutex.Lock()
	defer p.peerOmnihashMutex.Unlock()
	return []core.DiagnosticResult{
		newPeerOmnihashStatistic(p.peerOmnihashes),
	}
}

// NewProtocol creates a new instance of Protocol
func NewProtocol() Protocol {
	p := &protocol{
		peerOmnihashes:      make(map[p2p.PeerID]hash.SHA256Hash),
		peerOmnihashChannel: make(chan PeerOmnihash, 100),
		peerOmnihashMutex:   &sync.Mutex{},
		blocks:              newDAGBlocks(),
	}
	return p
}

func (p *protocol) Configure(p2pNetwork p2p.Adapter, graph dag.DAG, publisher dag.Publisher, payloadStore dag.PayloadStore, advertHashesInterval time.Duration, peerID p2p.PeerID) {
	p.p2pNetwork = p2pNetwork
	p.graph = graph
	p.payloadStore = payloadStore
	p.advertHashesInterval = advertHashesInterval
	p.peerID = peerID
	p.sender = defaultMessageSender{p2p: p.p2pNetwork}
	publisher.Subscribe(dag.AnyPayloadType, p.blocks.addTransaction)
}

func (p *protocol) Start() {
	go p.consumeMessages(p.p2pNetwork.ReceivedMessages())
	peerConnected, peerDisconnected := p.p2pNetwork.EventChannels()
	go p.startUpdatingDiagnostics(peerConnected, peerDisconnected)
	go p.startAdvertingHashes()
}

func (p protocol) Stop() {

}

func (p protocol) startAdvertingHashes() {
	ticker := time.NewTicker(p.advertHashesInterval)
	for {
		select {
		case <-ticker.C:
			p.sender.broadcastAdvertHashes(p.blocks.get())
		}
	}
}

func (p *protocol) startUpdatingDiagnostics(peerConnected chan p2p.Peer, peerDisconnected chan p2p.Peer) {
	for {
		p.updateDiagnostics(peerConnected, peerDisconnected)
	}
}

func (p *protocol) updateDiagnostics(peerConnected chan p2p.Peer, peerDisconnected chan p2p.Peer) {
	withLock := func(fn func()) {
		p.peerOmnihashMutex.Lock()
		defer p.peerOmnihashMutex.Unlock()
		fn()
	}
	select {
	case peer := <-peerConnected:
		withLock(func() {
			p.peerOmnihashes[peer.ID] = hash.EmptyHash()
		})
		break
	case peer := <-peerDisconnected:
		withLock(func() {
			delete(p.peerOmnihashes, peer.ID)
		})
		break
	case peerOmnihash := <-p.peerOmnihashChannel:
		withLock(func() {
			p.peerOmnihashes[peerOmnihash.Peer] = peerOmnihash.Hash
		})
		break
	}
}

func (p protocol) consumeMessages(queue p2p.MessageQueue) {
	for {
		peerMsg := queue.Get()
		if err := p.handleMessage(peerMsg); err != nil {
			log.Logger().Errorf("Error handling message (peer=%s): %v", peerMsg.Peer, err)
		}
	}
}

type chanPeerHashQueue struct {
	c chan *PeerOmnihash
}

func (q chanPeerHashQueue) Get() *PeerOmnihash {
	return <-q.c
}
