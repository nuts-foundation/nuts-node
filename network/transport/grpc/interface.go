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
	"context"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
)

// InboundStreamer allows Protocol implementations to expose gRPC streaming services.
type InboundStreamer interface {
	RegisterService(registrar grpc.ServiceRegistrar, acceptorCallback InboundStreamHandler)
}

// OutboundStreamer allows Protocol implementations to call a gRPC stream on a remote peer.
type OutboundStreamer interface {
	// OpenStream start a gRPC stream on a remote peer. It must not be blocking.
	OpenStream(context.Context, *grpc.ClientConn, func(stream grpc.ClientStream, method string) (transport.Peer, error)) (context.Context, error)
}

// InboundStreamHandler defines a function for accepting gRPC streams.
// The following values are returned:
// - `peer` which holds information about the specific peer.
// - `ctx` a context that can be used to wait until the connection has been closed.
// - `error` which indicates whether the stream has been accepted or not. If not accepted, the stream must be terminated and the error returned to the client.
type InboundStreamHandler func(serverStream grpc.ServerStream) (peer transport.Peer, ctx context.Context, err error)
