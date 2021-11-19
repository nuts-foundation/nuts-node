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

package logic

import (
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/p2p"
	"github.com/sirupsen/logrus"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
)

// protocol is thread-safe when callers use the Protocol interface
type protocol struct {
	adapter      p2p.Adapter
	graph        dag.DAG
	payloadStore dag.PayloadStore
	sender       messageSender
	// TODO: What if no-one is actually listening to this queue? Maybe we should create it when someone asks for it (lazy initialization)?
	receivedPeerHashes        *chanPeerHashQueue
	receivedTransactionHashes *chanPeerHashQueue

	// peerDiagnostics contains diagnostic information of the node's peers. The key contains the remote peer's ID. Access must be protected using peerDiagnosticsMutex
	peerDiagnostics      map[transport.PeerID]transport.Diagnostics
	peerDiagnosticsMutex *sync.Mutex

	// peerOmnihashes contains the omnihashes of our peers. Access must be protected using peerOmnihashMutex
	peerOmnihashes      map[transport.PeerID]hash.SHA256Hash
	peerOmnihashChannel chan PeerOmnihash
	peerOmnihashMutex   *sync.Mutex

	blocks                  dagBlocks
	missingPayloadCollector missingPayloadCollector

	advertHashesInterval           time.Duration
	advertDiagnosticsInterval      time.Duration
	collectMissingPayloadsInterval time.Duration
	// diagnosticsProvider is a function for collecting diagnostics from the local node which can be shared with peers.
	diagnosticsProvider func() transport.Diagnostics
	// peerID contains our own peer ID which can be logged for debugging purposes
	peerID    transport.PeerID
	publisher dag.Publisher
}

func (p *protocol) Diagnostics() []core.DiagnosticResult {
	var diagnostics []core.DiagnosticResult

	p.peerOmnihashMutex.Lock()
	diagnostics = append(diagnostics, newPeerOmnihashStatistic(p.peerOmnihashes))
	p.peerOmnihashMutex.Unlock()

	missingPayloads, err := p.missingPayloadCollector.findMissingPayloads()
	if err != nil {
		log.Logger().Errorf("Error while collecting missing payloads: %s", err)
	}
	diagnostics = append(diagnostics, &core.GenericDiagnosticResult{
		Title:   "v1_protocol_missing_payload_hashes",
		Outcome: missingPayloads,
	})

	return diagnostics
}

func (p *protocol) PeerDiagnostics() map[transport.PeerID]transport.Diagnostics {
	p.peerDiagnosticsMutex.Lock()
	defer p.peerDiagnosticsMutex.Unlock()
	// Clone map to avoid racy behaviour
	result := make(map[transport.PeerID]transport.Diagnostics, len(p.peerDiagnostics))
	for key, value := range p.peerDiagnostics {
		clone := value
		clone.Peers = append([]transport.PeerID(nil), value.Peers...)
		result[key] = clone
	}
	return result
}

// NewProtocol creates a new instance of Protocol
func NewProtocol(adapter p2p.Adapter, graph dag.DAG, publisher dag.Publisher, payloadStore dag.PayloadStore, diagnosticsProvider func() transport.Diagnostics) Protocol {
	p := &protocol{
		peerDiagnostics:      make(map[transport.PeerID]transport.Diagnostics, 0),
		peerDiagnosticsMutex: &sync.Mutex{},
		peerOmnihashes:       make(map[transport.PeerID]hash.SHA256Hash),
		peerOmnihashChannel:  make(chan PeerOmnihash, 100),
		peerOmnihashMutex:    &sync.Mutex{},
		blocks:               newDAGBlocks(),
		graph:                graph,
		payloadStore:         payloadStore,
		publisher:            publisher,
		diagnosticsProvider:  diagnosticsProvider,
		adapter:              adapter,
	}
	return p
}

func (p *protocol) Configure(advertHashesInterval time.Duration, advertDiagnosticsInterval time.Duration, collectMissingPayloadsInterval time.Duration, peerID transport.PeerID) {
	p.advertHashesInterval = advertHashesInterval
	p.advertDiagnosticsInterval = advertDiagnosticsInterval
	p.collectMissingPayloadsInterval = collectMissingPayloadsInterval
	p.peerID = peerID
	p.sender = defaultMessageSender{p2p: p.adapter, maxMessageSize: p2p.MaxMessageSizeInBytes}
	p.missingPayloadCollector = broadcastingMissingPayloadCollector{
		graph:        p.graph,
		payloadStore: p.payloadStore,
		sender:       p.sender,
	}
	p.publisher.Subscribe(dag.AnyPayloadType, p.blocks.addTransaction)
}

func (p *protocol) Start() {
	go p.consumeMessages(p.adapter.ReceivedMessages())
	peerConnected, peerDisconnected := p.adapter.EventChannels()
	go p.startUpdatingDiagnostics(peerConnected, peerDisconnected)
	go p.startAdvertingHashes()
	go p.startAdvertingDiagnostics()
	go p.startCollectingMissingPayloads()
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

func (p protocol) startAdvertingDiagnostics() {
	if p.advertDiagnosticsInterval.Nanoseconds() == 0 {
		log.Logger().Info("Diagnostics broadcasting is disabled.")
		return
	}
	ticker := time.NewTicker(p.advertDiagnosticsInterval)
	for {
		select {
		case <-ticker.C:
			p.sender.broadcastDiagnostics(p.diagnosticsProvider())
		}
	}
}

func (p protocol) startCollectingMissingPayloads() {
	if p.collectMissingPayloadsInterval.Nanoseconds() == 0 {
		log.Logger().Info("Collecting missing payloads is disabled.")
		return
	}
	ticker := time.NewTicker(p.collectMissingPayloadsInterval)
	for {
		select {
		case <-ticker.C:
			err := p.missingPayloadCollector.findAndQueryMissingPayloads()
			if err != nil {
				logrus.Infof("Error occured while querying missing payloads: %s", err)
			}
		}
	}
}

func (p *protocol) startUpdatingDiagnostics(peerConnected chan transport.Peer, peerDisconnected chan transport.Peer) {
	for {
		p.updateDiagnostics(peerConnected, peerDisconnected)
	}
}

func (p *protocol) updateDiagnostics(peerConnected chan transport.Peer, peerDisconnected chan transport.Peer) {
	select {
	case peer := <-peerConnected:
		withLock(p.peerOmnihashMutex, func() {
			p.peerOmnihashes[peer.ID] = hash.EmptyHash()
		})
		withLock(p.peerDiagnosticsMutex, func() {
			p.peerDiagnostics[peer.ID] = transport.Diagnostics{}
		})
		break
	case peer := <-peerDisconnected:
		withLock(p.peerOmnihashMutex, func() {
			delete(p.peerOmnihashes, peer.ID)
		})
		withLock(p.peerDiagnosticsMutex, func() {
			delete(p.peerDiagnostics, peer.ID)
		})
		break
	case peerOmnihash := <-p.peerOmnihashChannel:
		withLock(p.peerOmnihashMutex, func() {
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

func withLock(mux *sync.Mutex, fn func()) {
	mux.Lock()
	defer mux.Unlock()
	fn()
}
