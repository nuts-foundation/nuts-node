package v2

import (
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"github.com/stretchr/testify/assert"
	grpcLib "google.golang.org/grpc"
	"testing"
)

func Test_protocol_Start(t *testing.T) {
	// Doesn't do anything yet
	protocol{}.Start()
}

func Test_protocol_Configure(t *testing.T) {
	// Doesn't do anything yet
	protocol{}.Configure("")
}

func Test_protocol_Stop(t *testing.T) {
	// Doesn't do anything yet
	protocol{}.Stop()
}

func Test_protocol_Diagnostics(t *testing.T) {
	// Doesn't do anything yet
	assert.Empty(t, protocol{}.Diagnostics())
}

func Test_protocol_PeerDiagnostics(t *testing.T) {
	// Doesn't do anything yet
	assert.Empty(t, protocol{}.PeerDiagnostics())
}

func Test_protocol_MethodName(t *testing.T) {
	assert.Equal(t, "/v2.Protocol/Stream", protocol{}.MethodName())
}

func Test_protocol_CreateEnvelope(t *testing.T) {
	assert.Equal(t, &Envelope{}, protocol{}.CreateEnvelope())
}

func Test_protocol_UnwrapMessage(t *testing.T) {
	assert.Equal(t, &Envelope_TransactionPayloadQuery{}, protocol{}.UnwrapMessage(&Envelope{Message: &Envelope_TransactionPayloadQuery{}}))
}

func Test_protocol_send(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		connection := grpc.NewMockConnection(ctrl)
		connectionList := grpc.NewMockConnectionList(ctrl)
		connectionList.EXPECT().Get(transport.PeerID("123")).Return(connection)
		p := &protocol{}
		p.connectionList = connectionList
		msg := &Envelope_TransactionPayloadQuery{}
		connection.EXPECT().Send(p, &Envelope{Message: msg})

		err := p.send(transport.Peer{ID: "123"}, msg)

		assert.NoError(t, err)
	})
	t.Run("connection not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		connectionList := grpc.NewMockConnectionList(ctrl)
		connectionList.EXPECT().Get(transport.PeerID("123")).Return(nil)
		p := &protocol{}
		p.connectionList = connectionList

		err := p.send(transport.Peer{ID: "123"}, &Envelope_TransactionPayloadQuery{})

		assert.EqualError(t, err, "unable to send message, connection not found (peer=123@)")
	})
}

func Test_protocol_lifecycle(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		connectionList := grpc.NewMockConnectionList(ctrl)
		connectionManager := transport.NewMockConnectionManager(ctrl)
		s := grpcLib.NewServer()
		p := New(nil, nil)

		p.Start()

		p.Register(s, func(stream grpcLib.ServerStream) error {
			return nil
		}, connectionList, connectionManager)

		err := p.Handle(transport.Peer{ID: "123"}, &Envelope{})
		assert.EqualError(t, err, "envelope doesn't contain any (handleable) messages")

		p.Stop()
	})
}
