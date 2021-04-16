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
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	log "github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

// protocol is thread-safe when callers use the Protocol interface
type protocol struct {
	p2pNetwork        p2p.P2PNetwork
	graph             dag.DAG
	payloadStore      dag.PayloadStore
	signatureVerifier dag.TransactionSignatureVerifier
	// TODO: What if no-one is actually listening to this queue? Maybe we should create it when someone asks for it (lazy initialization)?
	receivedPeerHashes        *chanPeerHashQueue
	receivedTransactionHashes *chanPeerHashQueue
	peerHashes                map[p2p.PeerID][]hash.SHA256Hash

	// Cache statistics to avoid having to lock precious resources
	peerConsistencyHashStatistic peerConsistencyHashStatistic
	newPeerHashChannel           chan PeerHash
	blocks                       DAGBlocks

	advertHashesInterval time.Duration
	// peerID contains our own peer ID which can be logged for debugging purposes
	peerID p2p.PeerID
}

func (p *protocol) Diagnostics() []core.DiagnosticResult {
	return []core.DiagnosticResult{
		&p.peerConsistencyHashStatistic,
	}
}

func NewProtocol() Protocol {
	p := &protocol{
		peerHashes:                   make(map[p2p.PeerID][]hash.SHA256Hash),
		newPeerHashChannel:           make(chan PeerHash, 100),
		peerConsistencyHashStatistic: newPeerConsistencyHashStatistic(),
		blocks:                       MutexWrapDAGBlocks(NewDAGBlocks()),
	}
	return p
}

func (p *protocol) Configure(p2pNetwork p2p.P2PNetwork, graph dag.DAG, publisher dag.Publisher, payloadStore dag.PayloadStore, verifier dag.TransactionSignatureVerifier, advertHashesInterval time.Duration, peerID p2p.PeerID) {
	p.p2pNetwork = p2pNetwork
	p.graph = graph
	p.payloadStore = payloadStore
	p.advertHashesInterval = advertHashesInterval
	p.signatureVerifier = verifier
	p.peerID = peerID
	publisher.Subscribe(dag.AnyPayloadType, p.blocks.AddTransaction)
}

func (p *protocol) Start() {
	go p.consumeMessages(p.p2pNetwork.ReceivedMessages())
	go p.updateDiagnostics()
	go p.startAdvertingHashes()
}

func (p protocol) Stop() {

}

func (p protocol) startAdvertingHashes() {
	ticker := time.NewTicker(p.advertHashesInterval)
	for {
		select {
		case <-ticker.C:
			p.advertHashes()
		}
	}
}

func (p *protocol) updateDiagnostics() {
	// TODO: When to exit the loop?
	ticker := time.NewTicker(2 * time.Second)
	for {
		select {
		case <-ticker.C:
			// TODO: Make this garbage collection less dumb. Maybe we should be notified of disconnects rather than looping each time
			connectedPeers := p.p2pNetwork.Peers()
			var changed = false
			for peerId := range p.peerHashes {
				var present = false
				for _, connectedPeer := range connectedPeers {
					if peerId == connectedPeer.ID {
						present = true
					}
				}
				if !present {
					delete(p.peerHashes, peerId)
					changed = true
				}
			}
			if changed {
				p.peerConsistencyHashStatistic.copyFrom(p.peerHashes)
			}
		case peerHash := <-p.newPeerHashChannel:
			p.peerHashes[peerHash.Peer] = peerHash.Hashes
			p.peerConsistencyHashStatistic.copyFrom(p.peerHashes)
		}
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

func (p *protocol) handleMessage(peerMsg p2p.PeerMessage) error {
	peer := peerMsg.Peer
	networkMessage := peerMsg.Message
	switch msg := networkMessage.Message.(type) {
	case *transport.NetworkMessage_AdvertHashes:
		p.handleAdvertHashes(peer, msg.AdvertHashes)
	case *transport.NetworkMessage_TransactionListQuery:
		return p.handleTransactionListQuery(peer, msg.TransactionListQuery.BlockDate)
	case *transport.NetworkMessage_TransactionList:
		return p.handleTransactionList(peer, msg.TransactionList)
	case *transport.NetworkMessage_TransactionPayloadQuery:
		if msg.TransactionPayloadQuery.PayloadHash != nil {
			return p.handleTransactionPayloadQuery(peer, msg.TransactionPayloadQuery)
		}
	case *transport.NetworkMessage_TransactionPayload:
		if msg.TransactionPayload.PayloadHash != nil && msg.TransactionPayload.Data != nil {
			p.handleTransactionPayload(peer, msg.TransactionPayload)
		}
	}
	return nil
}

func createMessage() transport.NetworkMessage {
	return transport.NetworkMessage{}
}

type chanPeerHashQueue struct {
	c chan *PeerHash
}

func (q chanPeerHashQueue) Get() *PeerHash {
	return <-q.c
}
