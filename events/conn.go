/*
 * Nuts node
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

package events

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/nuts-foundation/nuts-node/events/log"
)

// Conn defines the methods required in the NATS connection structure
type Conn interface {
	// Close closes the connection
	Close()

	// JetStream returns the JetStream connection
	JetStream(opts ...nats.JSOpt) (nats.JetStreamContext, error)
}

// JetStreamContext is a copy of the nats.JetStreamContext interface that exists for mocking purposes
type JetStreamContext interface {
	nats.JetStreamContext
}

// ConnectionPool defines the interface for a NATS connection-pool
type ConnectionPool interface {
	// Acquire returns a NATS connection and JetStream context
	Acquire(ctx context.Context) (Conn, nats.JetStreamContext, error)
	// Shutdown closes all the connections
	Shutdown()
}

type connectionAndContext struct {
	conn Conn
	js   nats.JetStreamContext
}

// NATSConnectFunc defines the function signature for the NATS connection factory
type NATSConnectFunc func(url string, options ...nats.Option) (Conn, error)

// NATSConnectionPool implements a thread-safe pool of NATS connections (currently using a single NATS connection)
type NATSConnectionPool struct {
	config      Config
	conn        atomic.Value
	connecting  atomic.Value
	connectFunc NATSConnectFunc
}

// NewNATSConnectionPool creates a new NATSConnectionPool
func NewNATSConnectionPool(config Config) *NATSConnectionPool {
	return &NATSConnectionPool{
		config: config,
		connectFunc: func(url string, options ...nats.Option) (Conn, error) {
			return nats.Connect(url, options...)
		},
	}
}

// Acquire returns a NATS connection and JetStream context, it will connect if not already connected
func (pool *NATSConnectionPool) Acquire(ctx context.Context) (Conn, nats.JetStreamContext, error) {
	log.Logger().Trace("Trying to acquire a NATS connection")

	// If the connection is already set, return it
	data := pool.conn.Load()
	if data != nil {
		if conn, ok := data.(connectionAndContext); ok {
			return conn.conn, conn.js, nil
		}
	}

	// Are we already trying to connect? If so, just wait
	if !pool.connecting.CompareAndSwap(nil, true) {
		select {
		case <-ctx.Done():
			return nil, nil, context.Canceled
		case <-time.After(time.Second):
			return pool.Acquire(ctx)
		}
	}

	// We're the leader, let's connect!
	addr := fmt.Sprintf("%s:%d", pool.config.Nats.Hostname, pool.config.Nats.Port)

	log.Logger().Tracef("ConnectionState to %s", addr)

	for {
		conn, err := pool.connectFunc(
			addr,
			nats.RetryOnFailedConnect(true),
			nats.Timeout(time.Second*time.Duration(pool.config.Nats.Timeout)),
		)
		if err == nil {
			js, err := conn.JetStream()
			if err == nil {
				pool.conn.Store(connectionAndContext{conn, js})

				return conn, js, nil
			}
		}

		log.Logger().
			WithError(err).
			Errorf("Failed to connect to %s", addr)

		select {
		case <-ctx.Done():
			return nil, nil, context.Canceled
		case <-time.After(time.Second):
			continue
		}
	}
}

func (pool *NATSConnectionPool) Shutdown() {
	log.Logger().Trace("Shutting down NATS connection pool")

	// Just make sure no other connections are trying to connect while we're not connected
	if pool.connecting.Swap(true) == nil {
		return
	}

	// Only close the connection if it was opened in the first place
	data := pool.conn.Load()
	if data != nil {
		if conn, ok := data.(connectionAndContext); ok {
			conn.conn.Close()
		}
	}
}
