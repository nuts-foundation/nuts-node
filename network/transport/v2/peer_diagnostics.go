/*
 * Copyright (C) 2022 Nuts community
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

package v2

import (
	"context"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"sync"
	"time"
)

// peerDiagnosticsManager is responsible for managing peer diagnostics:
// - broadcasting our own peer diagnostics at a set interval
// - receiving peer diagnostics from our peers and aggregating them
type peerDiagnosticsManager struct {
	provider func() transport.Diagnostics
	sender   func(diagnostics transport.Diagnostics)
	mux      *sync.RWMutex
	received map[string]transport.Diagnostics
}

func newPeerDiagnosticsManager(provider func() transport.Diagnostics, sender func(diagnostics transport.Diagnostics)) *peerDiagnosticsManager {
	return &peerDiagnosticsManager{
		sender:   sender,
		provider: provider,
		mux:      &sync.RWMutex{},
		received: make(map[string]transport.Diagnostics),
	}
}

func (m *peerDiagnosticsManager) start(ctx context.Context, broadcastInterval time.Duration) {
	ticker := time.NewTicker(broadcastInterval)
	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			m.sender(m.provider())
		}
	}
}

func (m *peerDiagnosticsManager) handleReceived(peer transport.Peer, received *Diagnostics) {
	m.mux.Lock()
	defer m.mux.Unlock()

	diagnostics := transport.Diagnostics{
		Uptime:               time.Duration(received.Uptime) * time.Second,
		NumberOfTransactions: received.NumberOfTransactions,
		SoftwareVersion:      received.SoftwareVersion,
		SoftwareID:           received.SoftwareID,
	}
	for _, p := range received.Peers {
		diagnostics.Peers = append(diagnostics.Peers, transport.PeerID(p))
	}

	if certPem := peer.CertificateAsPem(); certPem != "" {
		diagnostics.Certificate = &certPem
	}
	m.received[peer.Key()] = diagnostics
}

func (m *peerDiagnosticsManager) get() map[string]transport.Diagnostics {
	m.mux.RLock()
	defer m.mux.RUnlock()
	result := make(map[string]transport.Diagnostics)
	for key, value := range m.received {
		// Make sure we copy the Peers slice to avoid data race when its used
		peers := append([]transport.PeerID{}, value.Peers...)
		value.Peers = peers
		result[key] = value
	}
	return result
}

func (m *peerDiagnosticsManager) remove(peer transport.Peer) {
	m.mux.Lock()
	defer m.mux.Unlock()
	delete(m.received, peer.Key())
}

func (m *peerDiagnosticsManager) add(peer transport.Peer) {
	m.mux.Lock()
	defer m.mux.Unlock()
	newDiagnostics := transport.Diagnostics{}
	if certPem := peer.CertificateAsPem(); certPem != "" {
		newDiagnostics.Certificate = &certPem
	}
	m.received[peer.Key()] = newDiagnostics
}
