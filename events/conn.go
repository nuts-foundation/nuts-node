package events

import "github.com/nats-io/nats.go"

type Conn interface {
	JetStream(opts ...nats.JSOpt) (nats.JetStreamContext, error)
}

type JetStreamContext interface {
	nats.JetStreamContext
	StreamInfo(stream string, opts ...nats.JSOpt) (*nats.StreamInfo, error)
	AddStream(cfg *nats.StreamConfig, opts ...nats.JSOpt) (*nats.StreamInfo, error)
	ChanSubscribe(subj string, ch chan *nats.Msg, opts ...nats.SubOpt) (*nats.Subscription, error)
	PublishMsg(m *nats.Msg, opts ...nats.PubOpt) (*nats.PubAck, error)
}
