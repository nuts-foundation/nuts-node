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

	"github.com/nuts-foundation/nuts-node/vcr/log"

	"github.com/nats-io/nats.go"
)

// Conn defines the methods required in the NATS connection structure
type Conn interface {
	Close()
	JetStream(opts ...nats.JSOpt) (nats.JetStreamContext, error)
}

// JetStreamContext defines the interface for the JetStreamContext of the NATS connection
type JetStreamContext interface {
	nats.JetStreamContext
	StreamInfo(stream string, opts ...nats.JSOpt) (*nats.StreamInfo, error)
	AddStream(cfg *nats.StreamConfig, opts ...nats.JSOpt) (*nats.StreamInfo, error)
	ChanSubscribe(subj string, ch chan *nats.Msg, opts ...nats.SubOpt) (*nats.Subscription, error)
	PublishMsg(m *nats.Msg, opts ...nats.PubOpt) (*nats.PubAck, error)
}

// ConnectionPool defines the interface for a NATS connection-pool
type ConnectionPool interface {
	Acquire(ctx context.Context) (Conn, JetStreamContext, error)
}

type connectionAndContext struct {
	conn Conn
	js   JetStreamContext
}

// NATSConnectionPool implements a thread-safe pool of NATS connections (currently using a single NATS connection)
type NATSConnectionPool struct {
	config     *Config
	conn       atomic.Value
	connecting atomic.Value
}

// Acquire returns a NATS connection and JetStream context, it will connect if not already connected
func (pool *NATSConnectionPool) Acquire(ctx context.Context) (Conn, JetStreamContext, error) {
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
			return nil, nil, ctx.Err()
		case <-time.After(time.Second):
			return pool.Acquire(ctx)
		}
	}

	// We're the leader, let's connect!
	addr := fmt.Sprintf("%s:%d", pool.config.Hostname, pool.config.Port)

	log.Logger().Tracef("connecting to %s", addr)

	for {
		conn, err := nats.Connect(addr, nats.RetryOnFailedConnect(true), nats.Timeout(time.Second*time.Duration(pool.config.Timeout)))
		if err == nil {
			js, err := conn.JetStream()
			if err == nil {
				pool.conn.Store(connectionAndContext{conn, js})

				return conn, js, nil
			}
		}

		log.Logger().Errorf("failed to connect to %s: %s", addr, err.Error())

		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(time.Second):
			continue
		}
	}
}
