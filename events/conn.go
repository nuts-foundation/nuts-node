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

// JetStreamContext defines the interface for the JetStreamContext of the NATS connection
type JetStreamContext interface {
	nats.JetStreamContext
}

// ConnectionPool defines the interface for a NATS connection-pool
type ConnectionPool interface {
	// Acquire returns a NATS connection and JetStream context
	Acquire(ctx context.Context) (Conn, JetStreamContext, error)
	// Shutdown closes all the connections
	Shutdown()
}

type connectionAndContext struct {
	conn Conn
	js   JetStreamContext
}

// NATSConnectFunc defines the function signature for the NATS connection factory
type NATSConnectFunc func(url string, options ...nats.Option) (Conn, error)

// NATSConnectionPool implements a thread-safe pool of NATS connections (currently using a single NATS connection)
type NATSConnectionPool struct {
	config      Config
	conn        atomic.Value
	connecting  chan struct{}
	connectFunc NATSConnectFunc
}

// NewNATSConnectionPool creates a new NATSConnectionPool
func NewNATSConnectionPool(config Config) *NATSConnectionPool {
	return &NATSConnectionPool{
		connecting: make(chan struct{}, 1),
		config:     config,
		connectFunc: func(url string, options ...nats.Option) (Conn, error) {
			return nats.Connect(url, options...)
		},
	}
}

// Acquire returns a NATS connection and JetStream context, it will connect if not already connected
func (pool *NATSConnectionPool) Acquire(ctx context.Context) (Conn, JetStreamContext, error) {
	log.Logger().Trace("Trying to acquire a NATS connection")
	// If the connection is already set, return it
	if data := pool.conn.Load(); data != nil {
		return data.(connectionAndContext).conn, data.(connectionAndContext).js, nil
	}

	// use channels to synchronize connection attempts and allow timing out/cancellation while waiting.
	ctx, cancel := context.WithTimeout(ctx, pool.config.Nats.Timeout)
	defer cancel()
	// either get the lock or time-out/cancelled
	select {
	case <-ctx.Done():
		// Cancelled or time-out
		return nil, nil, fmt.Errorf("time-out/cancelled while acquiring NATS connection: %w", ctx.Err())
	case pool.connecting <- struct{}{}:
		// lock acquired, we can now connect
		defer func() {
			<-pool.connecting
		}()
	}
	// connection could've been set while we were waiting
	if data := pool.conn.Load(); data != nil {
		return data.(connectionAndContext).conn, data.(connectionAndContext).js, nil
	}

	// now connect until it succeeds or is timed-out/cancelled
	addr := fmt.Sprintf("%s:%d", pool.config.Nats.Hostname, pool.config.Nats.Port)
	log.Logger().Tracef("Connecting to %s", addr)
	for {
		if ctx.Err() != nil {
			// Cancelled or time-out
			return nil, nil, fmt.Errorf("time-out/cancelled while acquiring NATS connection: %w", ctx.Err())
		}
		conn, err := pool.connectFunc(addr, nats.Timeout(pool.config.Nats.Timeout))
		if err == nil {
			js, err := conn.JetStream()
			if err == nil {
				pool.conn.Store(connectionAndContext{conn, js})

				return conn, js, nil
			}
		}
		log.Logger().
			WithError(err).
			Errorf("Failed to connect to NATS server at %s", addr)

		// wait a bit before reconnecting to avoid spinning failure
		select {
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("time-out/cancelled while acquiring NATS connection: %w", ctx.Err())
		case <-time.After(time.Second):
			continue
		}
	}
}

func (pool *NATSConnectionPool) Shutdown() {
	log.Logger().Trace("Shutting down NATS connection pool")

	// Only close the connection if it was opened in the first place
	if data := pool.conn.Load(); data != nil {
		data.(connectionAndContext).conn.Close()
	}
}
