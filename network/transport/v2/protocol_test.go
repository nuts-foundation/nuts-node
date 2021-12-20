package v2

import (
	"errors"
	"go.uber.org/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nats-io/nats.go"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	grpcLib "google.golang.org/grpc"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

type protocolMocks struct {
	Controller   *gomock.Controller
	Graph        *dag.MockDAG
	PayloadStore *dag.MockPayloadStore
	DocResolver  *vdr.MockDocResolver
	Decrypter    *crypto.MockDecrypter
}

func newTestProtocol(t *testing.T, nodeDID *did.DID) (*protocol, protocolMocks) {
	ctrl := gomock.NewController(t)

	docResolver := vdr.NewMockDocResolver(ctrl)
	decrypter := crypto.NewMockDecrypter(ctrl)
	graph := dag.NewMockDAG(ctrl)
	payloadStore := dag.NewMockPayloadStore(ctrl)
	nodeDIDResolver := transport.FixedNodeDIDResolver{}

	if nodeDID != nil {
		nodeDIDResolver.NodeDID = *nodeDID
	}

	proto := New(Config{
		Nats: NatsConfig{
			Port:     8080,
			Hostname: "localhost",
			Timeout:  30,
		},
	}, nodeDIDResolver, graph, payloadStore, docResolver, decrypter)

	return proto.(*protocol), protocolMocks{
		ctrl, graph, payloadStore, docResolver, decrypter,
	}
}

func TestProtocol_Configure(t *testing.T) {
	// Doesn't do anything yet
	protocol{}.Configure("")
}

func TestProtocol_Diagnostics(t *testing.T) {
	// Doesn't do anything yet
	assert.Empty(t, protocol{}.Diagnostics())
}

func TestProtocol_PeerDiagnostics(t *testing.T) {
	// Doesn't do anything yet
	assert.Empty(t, protocol{}.PeerDiagnostics())
}

func TestProtocol_MethodName(t *testing.T) {
	assert.Equal(t, "/v2.Protocol/Stream", protocol{}.MethodName())
}

func TestProtocol_CreateEnvelope(t *testing.T) {
	assert.Equal(t, &Envelope{}, protocol{}.CreateEnvelope())
}

func TestProtocol_UnwrapMessage(t *testing.T) {
	assert.Equal(t, &Envelope_TransactionPayloadQuery{}, protocol{}.UnwrapMessage(&Envelope{
		Message: &Envelope_TransactionPayloadQuery{},
	}))
}

func TestProtocol_send(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		connection := grpc.NewMockConnection(ctrl)
		connectionList := grpc.NewMockConnectionList(ctrl)
		connectionList.EXPECT().Get(grpc.ByPeerID("123")).Return(connection)

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
		connectionList.EXPECT().Get(grpc.ByPeerID("123")).Return(nil)

		p := &protocol{}
		p.connectionList = connectionList

		err := p.send(transport.Peer{ID: "123"}, &Envelope_TransactionPayloadQuery{})

		assert.EqualError(t, err, "unable to send message, connection not found (peer=123@)")
	})
}

func TestProtocol_lifecycle(t *testing.T) {
	ctrl := gomock.NewController(t)

	connectionList := grpc.NewMockConnectionList(ctrl)
	connectionManager := transport.NewMockConnectionManager(ctrl)

	s := grpcLib.NewServer()
	p, _ := newTestProtocol(t, nil)
	p.Start()

	p.Register(s, func(stream grpcLib.ServerStream) error {
		return nil
	}, connectionList, connectionManager)

	err := p.Handle(transport.Peer{ID: "123"}, &Envelope{})
	assert.EqualError(t, err, "envelope doesn't contain any (handleable) messages")

	p.Stop()
}

func TestProtocol_Start(t *testing.T) {
	ctrl := gomock.NewController(t)

	conn := events.NewMockConn(ctrl)
	js := events.NewMockJetStreamContext(ctrl)

	conn.EXPECT().JetStream().Return(js, nil)
	js.EXPECT().Subscribe(events.PrivateTransactionsSubject, gomock.Any()).Return(nil, nil)
	conn.EXPECT().Close()

	called := atomic.NewBool(false)

	proto, _ := newTestProtocol(t, nil)
	proto.natsConnectHandler = func(hostname string, port int, timeout time.Duration) (events.Conn, error) {
		called.Toggle()

		assert.Equal(t, 8080, port)
		assert.Equal(t, time.Second*30, timeout)
		assert.Equal(t, "localhost", hostname)

		return conn, nil
	}

	proto.Start()
	proto.Stop()

	time.Sleep(time.Second)

	assert.True(t, called.Load())
}

//nolint:funlen
func TestProtocol_HandlePrivateTx(t *testing.T) {
	keyDID, _ := did.ParseDIDURL("did:nuts:123#key1")
	testDID, _ := did.ParseDID("did:nuts:123")

	t.Run("errors when node DID is not set", func(t *testing.T) {
		proto, _ := newTestProtocol(t, nil)

		err := proto.handlePrivateTx(&nats.Msg{})
		assert.EqualError(t, err, "node DID is not set")
	})

	t.Run("errors when resolving the node DID document fails", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)

		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(nil, nil, errors.New("random error"))

		err := proto.handlePrivateTx(&nats.Msg{})
		assert.EqualError(t, err, "random error")
	})

	t.Run("errors when the transaction doesn't contain a valid PAL header", func(t *testing.T) {
		tx, _, _ := dag.CreateTestTransaction(1)
		proto, mocks := newTestProtocol(t, testDID)

		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)

		err := proto.handlePrivateTx(&nats.Msg{Data: tx.Data()})
		assert.EqualError(t, err, "PAL header is empty")
	})

	t.Run("errors when decryption fails because the key-agreement key could not be found", func(t *testing.T) {
		tx := dag.CreateSignedTestTransaction(1, time.Now(), [][]byte{{1}, {2}}, "text/plain", true)
		proto, mocks := newTestProtocol(t, testDID)

		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return(nil, crypto.ErrKeyNotFound)

		err := proto.handlePrivateTx(&nats.Msg{Data: tx.Data()})
		assert.Error(t, err)
	})

	t.Run("valid transaction fails when there is no connection available to the node", func(t *testing.T) {
		testDID, _ := did.ParseDID("did:nuts:123")

		tx := dag.CreateSignedTestTransaction(1, time.Now(), [][]byte{{1}, {2}}, "text/plain", true)
		proto, mocks := newTestProtocol(t, testDID)

		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return([]byte("did:nuts:123"), nil)

		connectionList := grpc.NewMockConnectionList(mocks.Controller)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*testDID)).Return(nil)

		proto.connectionList = connectionList

		err := proto.handlePrivateTx(&nats.Msg{Data: tx.Data()})
		assert.EqualError(t, err, "no connection found (DID=did:nuts:123)")
	})

	t.Run("valid transaction fails when sending the payload query errors", func(t *testing.T) {
		testDID, _ := did.ParseDID("did:nuts:123")

		tx := dag.CreateSignedTestTransaction(1, time.Now(), [][]byte{{1}, {2}}, "text/plain", true)
		proto, mocks := newTestProtocol(t, testDID)

		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return([]byte("did:nuts:123"), nil)

		conn := grpc.NewMockConnection(mocks.Controller)
		conn.EXPECT().Send(proto, &Envelope{Message: &Envelope_TransactionPayloadQuery{
			TransactionPayloadQuery: &TransactionPayloadQuery{
				TransactionRef: tx.Ref().Slice(),
			},
		}}).Return(errors.New("random error"))

		connectionList := grpc.NewMockConnectionList(mocks.Controller)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*testDID)).Return(conn)

		proto.connectionList = connectionList

		err := proto.handlePrivateTx(&nats.Msg{Data: tx.Data()})
		assert.EqualError(t, err, "random error")
	})

	t.Run("valid transaction is handled successfully", func(t *testing.T) {
		testDID, _ := did.ParseDID("did:nuts:123")

		tx := dag.CreateSignedTestTransaction(1, time.Now(), [][]byte{{1}, {2}}, "text/plain", true)
		proto, mocks := newTestProtocol(t, testDID)

		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return([]byte("did:nuts:123"), nil)

		conn := grpc.NewMockConnection(mocks.Controller)
		conn.EXPECT().Send(proto, &Envelope{Message: &Envelope_TransactionPayloadQuery{
			TransactionPayloadQuery: &TransactionPayloadQuery{
				TransactionRef: tx.Ref().Slice(),
			},
		}}).Return(nil)

		connectionList := grpc.NewMockConnectionList(mocks.Controller)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*testDID)).Return(conn)

		proto.connectionList = connectionList

		err := proto.handlePrivateTx(&nats.Msg{Data: tx.Data()})
		assert.NoError(t, err)
	})
}
