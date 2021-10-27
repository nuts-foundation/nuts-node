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
	"sync/atomic"

	"github.com/nats-io/nats.go"
)

// Stream contains configuration for a NATS stream both on the server and client side
type Stream interface {
	Config() *nats.StreamConfig
	ClientOpts() []nats.SubOpt
	Subscribe(conn Conn, subject string) (chan *nats.Msg, error)
}

type stream struct {
	config     *nats.StreamConfig
	clientOpts []nats.SubOpt
	created    atomic.Value
}

func (stream *stream) Config() *nats.StreamConfig {
	return stream.config
}

func (stream *stream) ClientOpts() []nats.SubOpt {
	return stream.clientOpts[:]
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

func (stream *stream) Subscribe(conn Conn, subject string) (chan *nats.Msg, error) {
	ctx, err := conn.JetStream()
	if err != nil {
		return nil, err
	}

	if err := stream.create(ctx); err != nil {
		return nil, err
	}

	msgChan := make(chan *nats.Msg)

	_, err = ctx.ChanSubscribe(subject, msgChan)
	if err != nil {
		return nil, err
	}

	return msgChan, nil
}

// NewDisposableStream configures a stream with default settings for messages with low priority
func NewDisposableStream(name string, subjects []string, maxMessages int64) Stream {
	return NewStream(&nats.StreamConfig{
		Name:      name,
		Subjects:  subjects,
		MaxMsgs:   maxMessages,
		Retention: nats.LimitsPolicy,
		Storage:   nats.MemoryStorage,
		Discard:   nats.DiscardOld,
	}, []nats.SubOpt{
		nats.AckNone(),
		nats.DeliverNew(),
	})
}

// NewStream configures a stream without any default settings
func NewStream(config *nats.StreamConfig, clientOpts []nats.SubOpt) Stream {
	return &stream{
		config:     config,
		clientOpts: clientOpts,
	}
}
