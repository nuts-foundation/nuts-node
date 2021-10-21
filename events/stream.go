package events

import (
	"errors"
	"github.com/nats-io/nats.go"
	"sync/atomic"
)

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
)

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

func (stream *stream) create(conn *nats.Conn) error {
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

func (stream *stream) Subscribe(conn *nats.Conn, subject string) (chan *nats.Msg, error) {
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
