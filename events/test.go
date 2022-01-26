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

package events

import (
	"context"
	"sync"

	"github.com/nats-io/nats.go"
)

type stubConn struct {
	Conn
	JetStreamContext
}

// PublishAsync publishes an event to the given subject
func (conn *stubConn) PublishAsync(_subj string, _data []byte, _opts ...nats.PubOpt) (nats.PubAckFuture, error) {
	return nil, nil
}

// Subscribe creates a subscription on the given subject
func (conn *stubConn) Subscribe(_subj string, _cb nats.MsgHandler, _opts ...nats.SubOpt) (*nats.Subscription, error) {
	return &nats.Subscription{}, nil
}

// JetStream returns the JetStream context
func (conn *stubConn) JetStream(_ ...nats.JSOpt) (nats.JetStreamContext, error) {
	return conn, nil
}

// StreamInfo returns the stream information
func (conn *stubConn) StreamInfo(_ string, _ ...nats.JSOpt) (*nats.StreamInfo, error) {
	return &nats.StreamInfo{}, nil
}

// AddStream adds a stream to the server
func (conn *stubConn) AddStream(cfg *nats.StreamConfig, opts ...nats.JSOpt) (*nats.StreamInfo, error) {
	return &nats.StreamInfo{}, nil
}

type stubEventManager struct {
	pool ConnectionPool
	once sync.Once
}

func NewStubEventManager() Event {
	return &stubEventManager{}
}

func (s *stubEventManager) Pool() ConnectionPool {
	s.once.Do(func() {
		s.pool = NewStubConnectionPool()
	})
	return s.pool
}

type stubConnectionPool struct {
	conn *stubConn
}

// NewStubConnectionPool returns a new ConnectionPool used for testing
func NewStubConnectionPool() ConnectionPool {
	return &stubConnectionPool{
		conn: &stubConn{},
	}
}

// Acquire returns a connection from the pool
func (pool *stubConnectionPool) Acquire(_ context.Context) (Conn, JetStreamContext, error) {
	return pool.conn, pool.conn, nil
}

// Shutdown closes the pool
func (pool *stubConnectionPool) Shutdown() {
}
