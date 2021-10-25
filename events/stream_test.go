package events

import (
	"github.com/golang/mock/gomock"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
)

func TestStream_Middleware(t *testing.T) {
	msg := nats.NewMsg("original-subject")

	err := RetryStream.middleware(msg)
	assert.NoError(t, err)

	assert.Equal(t, "nuts.retry", msg.Subject)
	assert.Equal(t, "original-subject", msg.Header.Get("subject"))
	assert.Equal(t, "0", msg.Header.Get("retries"))
}

func TestStream_Publish(t *testing.T) {
	jsMock := NewMockJetStreamContext(gomock.NewController(t))
	jsMock.EXPECT().StreamInfo(DisposableStream.Config().Name).Return(nil, nil)
	jsMock.EXPECT().PublishMsg(nats.NewMsg("test"))

	conn := NewMockConn(gomock.NewController(t))
	conn.EXPECT().JetStream().Return(jsMock, nil)
	conn.EXPECT().JetStream().Return(jsMock, nil)

	err := DisposableStream.Publish(conn, nats.NewMsg("test"))
	assert.NoError(t, err)
}
