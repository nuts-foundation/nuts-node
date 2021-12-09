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
	"fmt"
	"github.com/nats-io/nats.go"
	"time"
)

// Conn defines the methods required in the NATS connection structure
type Conn interface {
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

// Connect connects to a NATS server based on the hostname and port
func Connect(hostname string, port int, timeout time.Duration) (Conn, error) {
	return nats.Connect(
		fmt.Sprintf("%s:%d", hostname, port),
		nats.RetryOnFailedConnect(true),
		nats.Timeout(timeout),
	)
}
