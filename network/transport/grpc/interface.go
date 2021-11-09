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
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
)

// ServiceImplementor allows Protocol implementations to expose a gRPC service.
type ServiceImplementor interface {
	RegisterService(registrar grpc.ServiceRegistrar, acceptorCallback StreamAcceptor)
}

// StreamAcceptor defines a function for accepting gRPC streams.
// The following values are returned:
// - `accepted` which indicates whether the stream has been accepted or not. If not accepted, the stream must be terminated.
// - `peer` which holds information about the specific peer.
// - `closer` channel which is used to signal when the stream must be closed.
type StreamAcceptor func(serverStream grpc.ServerStream) (accepted bool, peer transport.Peer, closer chan struct{})
