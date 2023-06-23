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

package transport

import (
	"github.com/nuts-foundation/nuts-node/core"
)

// Protocol is a self-contained process that can exchange network data (e.g. DAG transactions or private credentials) with other parties on the network.
type Protocol interface {
	// Configure configures the Protocol implementation, must be called before Start().
	Configure(peerID PeerID) error
	// Start starts the Protocol implementation.
	Start() error
	// Stop stops the Protocol implementation.
	Stop()
	// Diagnostics collects and returns diagnostical information on the protocol.
	Diagnostics() []core.DiagnosticResult
	// PeerDiagnostics collects and returns diagnostical information on the peers the protocol is communicating with.
	PeerDiagnostics() map[string]Diagnostics
	// Version returns the version of the protocol
	Version() int
}
