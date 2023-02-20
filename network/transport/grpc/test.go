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

package grpc

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc/status"
)

// StubConnectionList is a stub implementation of the transport.ConnectionList interface
type StubConnectionList struct {
	Conn *StubConnection
}

// Get returns the connection for the given query
func (s *StubConnectionList) Get(query ...Predicate) Connection {
	if s.Conn == nil {
		return nil
	}

	for _, predicate := range query {
		if !predicate.Match(s.Conn) {
			return nil
		}
	}

	return s.Conn
}

// All returns all connections
func (s StubConnectionList) All() []Connection {
	if s.Conn == nil {
		return nil
	}
	return []Connection{s.Conn}
}

// AllMatching returns all connections
func (s StubConnectionList) AllMatching(_ ...Predicate) []Connection {
	return s.All()
}

// StubConnection is a stub implementation of the Connection interface
type StubConnection struct {
	Open          bool
	NodeDID       did.DID
	SentMsgs      []interface{}
	PeerID        transport.PeerID
	Authenticated bool
}

// Send sends a message to the connection
func (s *StubConnection) Send(_ Protocol, envelope interface{}, _ bool) error {
	s.SentMsgs = append(s.SentMsgs, envelope)

	return nil
}

// Peer returns the peer information of the connection
func (s *StubConnection) Peer() transport.Peer {
	return transport.Peer{
		ID:            s.PeerID,
		NodeDID:       s.NodeDID,
		Authenticated: s.Authenticated,
	}
}

// IsConnected returns true if the connection is connected
func (s *StubConnection) IsConnected() bool {
	return s.Open
}

// IsProtocolConnected returns true if the connection is connected for the given protocol
func (s *StubConnection) IsProtocolConnected(_ Protocol) bool {
	return s.Open
}

// IsAuthenticated returns whether teh given connection is authenticated.
func (s *StubConnection) IsAuthenticated() bool {
	return s.Authenticated
}

func (s *StubConnection) CloseError() *status.Status {
	panic("implement me")
}

func (s *StubConnection) SetErrorStatus(_ *status.Status) {
	panic("implement me")
}

func (s *StubConnection) disconnect() {
	panic("implement me")
}

func (s *StubConnection) waitUntilDisconnected() {
	panic("implement me")
}

func (s *StubConnection) registerStream(protocol Protocol, stream Stream) bool {
	panic("implement me")
}

func (s *StubConnection) verifyOrSetPeerID(_ transport.PeerID) bool {
	panic("implement me")
}

func (s *StubConnection) setPeer(_ transport.Peer) {
	panic("implement me")
}
