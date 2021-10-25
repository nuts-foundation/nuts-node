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
	Subscribe(conn *nats.Conn, subject string) (chan *nats.Msg, error)
}

var (
	// PrivateCredentialStream defines configuration for the stream where all private credentials will be sent to
	PrivateCredentialStream = &stream{
		config: &nats.StreamConfig{
			Name: "nuts-private-credentials",
			Subjects: []string{
				"nuts.vcr.private.*",
			},
			Retention:    nats.WorkQueuePolicy,
			MaxConsumers: 1,
			MaxMsgs:      10,
			Storage:      nats.FileStorage,
			Discard:      nats.DiscardNew,
		},
		clientOpts: []nats.SubOpt{
			nats.AckExplicit(),
			nats.ManualAck(),
			nats.Durable("private-credential-stream-consumer"),
		},
	}

	// DisposableStream defines configuration for the stream where it doesn't matter if messages are dropped
	DisposableStream = &stream{
		config: &nats.StreamConfig{
			Name: "nuts-disposable",
			Subjects: []string{
				"nuts.auth.metrics.*",
				"nuts.crl.metrics.*",
				"nuts.network.metrics.*",
				"nuts.vcr.metrics.*",
				"nuts.vdr.metrics.*",
			},
			MaxMsgs:   100,
			Retention: nats.LimitsPolicy,
			Storage:   nats.MemoryStorage,
			Discard:   nats.DiscardOld,
		},
		clientOpts: []nats.SubOpt{
			nats.AckNone(),
			nats.DeliverNew(),
		},
	}

	// RetryStream defines configuration for the stream where messages will be sent back to another stream based on the time
	RetryStream = &stream{
		config: &nats.StreamConfig{
			Name: "nats-retries",
			Subjects: []string{
				"nuts.retry",
			},
			Retention: nats.WorkQueuePolicy,
			Storage:   nats.FileStorage,
			Discard:   nats.DiscardNew,
		},
		clientOpts: []nats.SubOpt{
			nats.AckExplicit(),
			nats.ManualAck(),
		},
		middleware: func(msg *nats.Msg) error {
			msg.Header.Set("subject", msg.Subject)
			msg.Header.Set("retries", "0")
			msg.Subject = "nuts.retry"

			return nil
		},
	}
)

type stream struct {
	config     *nats.StreamConfig
	clientOpts []nats.SubOpt
	created    atomic.Value
	middleware func(msg *nats.Msg) error
}

func (stream *stream) Config() *nats.StreamConfig {
	return stream.config
}

func (stream *stream) ClientOpts() []nats.SubOpt {
	return stream.clientOpts[:]
}

func (stream *stream) create(conn Conn) error {
	if stream.created.Load() != nil {
		return nil
	}

	js, err := conn.JetStream()
	if err != nil {
		return err
	}

	_, err = js.StreamInfo(stream.config.Name)
	if errors.Is(err, nats.ErrStreamNotFound) {
		_, err = js.AddStream(stream.config)
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
	if err := stream.create(conn); err != nil {
		return nil, err
	}

	ctx, err := conn.JetStream()
	if err != nil {
		return nil, err
	}

	var msgChan chan *nats.Msg

	_, err = ctx.ChanSubscribe(subject, msgChan)
	if err != nil {
		return nil, err
	}

	return msgChan, nil
}

func (stream *stream) Publish(conn Conn, msg *nats.Msg, opts ...nats.PubOpt) error {
	if stream.middleware != nil {
		if err := stream.middleware(msg); err != nil {
			return err
		}
	}

	if err := stream.create(conn); err != nil {
		return err
	}

	ctx, err := conn.JetStream()
	if err != nil {
		return err
	}

	_, err = ctx.PublishMsg(msg, opts...)
	return err
}
