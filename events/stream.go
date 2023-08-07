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
	"errors"
	"github.com/nats-io/nats.go"
	"sync/atomic"
)

const (
	// TransactionsStream is the stream name on which transactions are stored
	TransactionsStream = "TRANSACTIONS"
	// DataStream is the stream name on which the data/payload is stored (VCs/DIDDocuments)
	DataStream = "DATA"
	// ReprocessStream is the stream name used to rebuild the VDR/VCR
	ReprocessStream = "REPROCESS"
)

// Stream contains configuration for a NATS stream both on the server and client side
type Stream interface {
	// Config returns the server configuration of the NATS stream
	Config() *nats.StreamConfig
	// Subscribe to a stream on the NATS server
	// The consumerName is used as the durable config name.
	// The subjectFilter can be used to filter messages on the stream (eg: TRANSACTIONS.* or DATA.VerificableCredential)
	Subscribe(conn Conn, consumerName string, subjectFilter string, handler nats.MsgHandler) error
}

type stream struct {
	config  *nats.StreamConfig
	created atomic.Value
	durable bool
}

func (stream *stream) Config() *nats.StreamConfig {
	return stream.config
}

func (stream *stream) create(ctx JetStreamContext) error {
	if stream.created.Load() != nil {
		return nil
	}

	_, err := ctx.StreamInfo(stream.config.Name)
	if errors.Is(err, nats.ErrStreamNotFound) {
		_, err = ctx.AddStream(stream.config)
		if err != nil {
			return err
		}

		stream.created.Store(true)
	} else if err != nil {
		return err
	}

	return nil
}

func (stream *stream) Subscribe(conn Conn, consumerName string, subjectFilter string, handler nats.MsgHandler) error {
	ctx, err := conn.JetStream()
	if err != nil {
		return err
	}

	if err := stream.create(ctx); err != nil {
		return err
	}

	opts := []nats.SubOpt{
		nats.BindStream(stream.config.Name),
		nats.ManualAck(),
		nats.AckExplicit(),
		nats.DeliverNew(),
		nats.MaxDeliver(5),       // number of redelivery attempts
		nats.MaxAckPending(1000), // maximum number of messages sent by the server to the client without an ack, should fit within Subscriber limits (sub.SetPendingLimits())
	}
	if stream.durable {
		opts = append(opts, nats.Durable(consumerName))
	}

	_, err = ctx.Subscribe(subjectFilter, handler, opts...)
	if err != nil {
		return err
	}

	return nil
}

// NewDisposableStream configures a stream with memory storage, discard old policy and a message limit retention policy
func NewDisposableStream(name string, subjects []string, maxMessages int64) Stream {
	return newStream(&nats.StreamConfig{
		Name:      name,
		Subjects:  subjects,
		MaxMsgs:   maxMessages,
		Retention: nats.LimitsPolicy,
		Storage:   nats.MemoryStorage,
		Discard:   nats.DiscardOld,
	}, false)
}

// newStream configures a stream without any default settings
func newStream(config *nats.StreamConfig, durable bool) Stream {
	return &stream{
		config:  config,
		durable: durable,
	}
}
