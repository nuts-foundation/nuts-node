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

// Protocol defines the API for streaming gRPC protocol implementations.
type Protocol interface {
	transport.Protocol

	// MethodName returns the fully qualified name of the gRPC stream.
	MethodName() string
	// CreateClientStream creates a new client for the gRPC stream.
	CreateClientStream(outgoingContext context.Context, grpcConn grpc.ClientConnInterface) (grpc.ClientStream, error)
	// Register registers the protocol implementation.
	Register(registrar grpc.ServiceRegistrar, acceptor func(stream grpc.ServerStream) error, connectionList ConnectionList, connectionManager transport.ConnectionManager)

	// CreateEnvelope is called to create a new, empty envelope, required for receiving messages.
	CreateEnvelope() interface{}
	// Handle is called with to let the protocol handle a received message.
	Handle(connection Connection, envelope interface{}) error
	// UnwrapMessage is used to extract the inner message from the envelope.
	UnwrapMessage(envelope interface{}) interface{}
	// GetMessageType returns a string key identifying the message type.
	GetMessageType(envelope interface{}) string
}

// Stream bundles common functions from grpc.ServerStream and grpc.ClientStream, providing a common interface.
type Stream interface {
	Context() context.Context
	SendMsg(m interface{}) error
	RecvMsg(m interface{}) error
}

// These interfaces are here for mocking purposes.

// Conn is a wrapper around grpc.ClientConnInterface
type Conn interface {
	grpc.ClientConnInterface
}

// ClientStream is a wrapper around grpc.ClientStream
type ClientStream interface {
	grpc.ClientStream
}
