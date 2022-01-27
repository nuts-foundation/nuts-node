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
	"context"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
)

// protocol is thread-safe when callers use the Protocol interface
type protocol struct {
	txState     dag.State
	sender      messageSender
	connections grpc.ConnectionList
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
	peerID transport.PeerID

	ctx       context.Context
	ctxCancel func()
}

func (p *protocol) Diagnostics() []core.DiagnosticResult {
	var diagnostics []core.DiagnosticResult

	p.peerOmnihashMutex.Lock()
	// Clean up diagnostics of disconnected peers
	for peerID := range p.peerOmnihashes {
		connection := p.connections.Get(grpc.ByPeerID(peerID))
		if connection == nil || !connection.IsConnected() {
			delete(p.peerOmnihashes, peerID)
		}
	}
	diagnostics = append(diagnostics, newPeerOmnihashStatistic(p.peerOmnihashes))
	p.peerOmnihashMutex.Unlock()

	missingPayloads, err := p.missingPayloadCollector.findMissingPayloads()
	if err != nil {
		log.Logger().Errorf("Error while collecting missing payloads: %s", err)
	}
	diagnostics = append(diagnostics, &core.GenericDiagnosticResult{
		Title:   "v1_missing_payload_hashes",
		Outcome: missingPayloads,
	})

	return diagnostics
}

func (p *protocol) PeerDiagnostics() map[transport.PeerID]transport.Diagnostics {
	p.peerDiagnosticsMutex.Lock()
	defer p.peerDiagnosticsMutex.Unlock()
	// Clone map to avoid racy behaviour
	result := make(map[transport.PeerID]transport.Diagnostics)
	for peerID, value := range p.peerDiagnostics {
		// Clean up diagnostics of disconnected peers on the go
		connection := p.connections.Get(grpc.ByPeerID(peerID))
		if connection == nil || !connection.IsConnected() {
			delete(p.peerDiagnostics, peerID)
			continue
		}
		clone := value
		clone.Peers = append([]transport.PeerID(nil), value.Peers...)
		result[peerID] = clone
	}
	return result
}

// NewProtocol creates a new instance of Protocol
func NewProtocol(gateway MessageGateway, connections grpc.ConnectionList, txState dag.State, diagnosticsProvider func() transport.Diagnostics) Protocol {
	p := &protocol{
		peerDiagnostics:      make(map[transport.PeerID]transport.Diagnostics, 0),
		peerDiagnosticsMutex: &sync.Mutex{},
		peerOmnihashes:       make(map[transport.PeerID]hash.SHA256Hash),
		peerOmnihashChannel:  make(chan PeerOmnihash, 100),
		peerOmnihashMutex:    &sync.Mutex{},
		blocks:               newDAGBlocks(),
		txState:              txState,
		diagnosticsProvider:  diagnosticsProvider,
		connections:          connections,
		sender: defaultMessageSender{
			gateway:        gateway,
			maxMessageSize: grpc.MaxMessageSizeInBytes,
		},
	}
	return p
}

func (p *protocol) Configure(advertHashesInterval time.Duration, advertDiagnosticsInterval time.Duration, collectMissingPayloadsInterval time.Duration, peerID transport.PeerID) {
	p.advertHashesInterval = advertHashesInterval
	p.advertDiagnosticsInterval = advertDiagnosticsInterval
	p.collectMissingPayloadsInterval = collectMissingPayloadsInterval
	p.peerID = peerID
	p.missingPayloadCollector = broadcastingMissingPayloadCollector{
		txState: p.txState,
		sender:  p.sender,
	}
	p.txState.Subscribe(dag.TransactionAddedEvent, dag.AnyPayloadType, p.blocks.addTransaction)
}

func (p *protocol) Start() {
	p.ctx, p.ctxCancel = context.WithCancel(context.Background())
	go p.startUpdatingDiagnostics(p.ctx)
	go p.startAdvertingHashes(p.ctx)
	go p.startAdvertingDiagnostics(p.ctx)
	go p.startCollectingMissingPayloads(p.ctx)
}

func (p protocol) Stop() {
	if p.ctxCancel != nil {
		p.ctxCancel()
	}
}

func (p protocol) startAdvertingHashes(ctx context.Context) {
	ticker := time.NewTicker(p.advertHashesInterval)
	done := ctx.Done()
	for {
		select {
		case <-ticker.C:
			p.sender.broadcastAdvertHashes(p.blocks.get())
		case <-done:
			return
		}
	}
}

func (p protocol) startAdvertingDiagnostics(ctx context.Context) {
	if p.advertDiagnosticsInterval.Nanoseconds() == 0 {
		log.Logger().Info("Diagnostics broadcasting is disabled.")
		return
	}
	ticker := time.NewTicker(p.advertDiagnosticsInterval)
	done := ctx.Done()
	for {
		select {
		case <-ticker.C:
			p.sender.broadcastDiagnostics(p.diagnosticsProvider())
		case <-done:
			return
		}
	}
}

func (p protocol) startCollectingMissingPayloads(ctx context.Context) {
	if p.collectMissingPayloadsInterval.Nanoseconds() == 0 {
		log.Logger().Info("Collecting missing payloads is disabled.")
		return
	}
	ticker := time.NewTicker(p.collectMissingPayloadsInterval)
	done := ctx.Done()
	for {
		select {
		case <-ticker.C:
			err := p.missingPayloadCollector.findAndQueryMissingPayloads()
			if err != nil {
				log.Logger().Infof("Error occured while querying missing payloads: %s", err)
			}
		case <-done:
			return
		}
	}
}

func (p *protocol) startUpdatingDiagnostics(ctx context.Context) {
	done := ctx.Done()
	for {
		if !p.updateDiagnostics(done) {
			return
		}
	}
}

func (p *protocol) updateDiagnostics(done <-chan struct{}) bool {
	select {
	case peerOmnihash := <-p.peerOmnihashChannel:
		withLock(p.peerOmnihashMutex, func() {
			p.peerOmnihashes[peerOmnihash.Peer] = peerOmnihash.Hash
		})
		return true
	case <-done:
		return false
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
