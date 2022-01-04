package v2

import (
	"context"
	"errors"
	"fmt"
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
	Controller           *gomock.Controller
	EventsConnectionPool *events.MockConnectionPool
	Graph                *dag.MockDAG
	PayloadRetrier       *MockRetriable
	PayloadStore         *dag.MockPayloadStore
	DocResolver          *vdr.MockDocResolver
	Decrypter            *crypto.MockDecrypter
}

func newTestProtocol(t *testing.T, nodeDID *did.DID) (*protocol, protocolMocks) {
	ctrl := gomock.NewController(t)

	docResolver := vdr.NewMockDocResolver(ctrl)
	decrypter := crypto.NewMockDecrypter(ctrl)
	graph := dag.NewMockDAG(ctrl)
	payloadRetrier := NewMockRetriable(ctrl)
	payloadStore := dag.NewMockPayloadStore(ctrl)
	nodeDIDResolver := transport.FixedNodeDIDResolver{}
	eventsConnectionPool := events.NewMockConnectionPool(ctrl)

	if nodeDID != nil {
		nodeDIDResolver.NodeDID = *nodeDID
	}

	proto := New(Config{}, eventsConnectionPool, nodeDIDResolver, graph, payloadStore, docResolver, decrypter)
	proto.(*protocol).payloadRetrier = payloadRetrier

	return proto.(*protocol), protocolMocks{
		ctrl, eventsConnectionPool, graph, payloadRetrier, payloadStore, docResolver, decrypter,
	}
}

func TestProtocol_Configure(t *testing.T) {
	// Doesn't do anything yet
	p := &protocol{}
	p.Configure("")
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
	p, mocks := newTestProtocol(t, nil)
	mocks.PayloadRetrier.EXPECT().Start().Return(nil)
	mocks.PayloadRetrier.EXPECT().Close()
	p.eventsConnectionPool = events.NewStubConnectionPool()
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
	js.EXPECT().Subscribe(events.PrivateTransactionsSubject, gomock.Any(), gomock.Any()).Return(nil, nil)

	proto, mocks := newTestProtocol(t, nil)

	mocks.PayloadRetrier.EXPECT().Start().Return(nil)
	mocks.PayloadRetrier.EXPECT().Close()
	mocks.EventsConnectionPool.EXPECT().Acquire(gomock.Any()).Return(conn, js, nil)

	proto.Start()
	proto.Stop()

	time.Sleep(7 * time.Second)
}

func TestProtocol_HandlePrivateTx(t *testing.T) {
	tx, _, _ := dag.CreateTestTransaction(0)

	t.Run("ok - event passed as job to payloadRetrier", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.PayloadRetrier.EXPECT().Add(tx.Ref())

		err := proto.handlePrivateTx(&nats.Msg{Data: tx.Data()})

		assert.NoError(t, err)
	})

	t.Run("error - can't parse transaction", func(t *testing.T) {
		proto, _ := newTestProtocol(t, nil)

		err := proto.handlePrivateTx(&nats.Msg{})

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "unable to parse transaction: invalid byte sequence")
	})

	t.Run("error - can't add to retrier", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.PayloadRetrier.EXPECT().Add(tx.Ref()).Return(errors.New("b00m!"))

		err := proto.handlePrivateTx(&nats.Msg{Data: tx.Data()})

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "b00m!")
	})
}

//nolint:funlen
func TestProtocol_HandlePrivateTxRetry(t *testing.T) {
	keyDID, _ := did.ParseDIDURL("did:nuts:123#key1")
	testDID, _ := did.ParseDID("did:nuts:123")
	tx, _, _ := dag.CreateTestTransaction(0)
	txOk := dag.CreateSignedTestTransaction(1, time.Now(), [][]byte{{1}, {2}}, "text/plain", true)

	t.Run("errors when node DID is not set", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.Graph.EXPECT().Get(context.Background(), txOk.Ref()).Return(txOk, nil)

		err := proto.handlePrivateTxRetryErr(txOk.Ref())
		assert.EqualError(t, err, fmt.Sprintf("failed to decrypt PAL header (ref=%s): node DID is not set", txOk.Ref()))
	})

	t.Run("errors when resolving the node DID document fails", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.Graph.EXPECT().Get(context.Background(), txOk.Ref()).Return(txOk, nil)
		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(nil, nil, errors.New("random error"))

		err := proto.handlePrivateTxRetryErr(txOk.Ref())
		assert.EqualError(t, err, fmt.Sprintf("failed to decrypt PAL header (ref=%s): random error", txOk.Ref()))
	})

	t.Run("errors when the transaction doesn't contain a valid PAL header", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)

		mocks.Graph.EXPECT().Get(context.Background(), tx.Ref()).Return(tx, nil)

		err := proto.handlePrivateTxRetryErr(tx.Ref())
		assert.EqualError(t, err, fmt.Sprintf("PAL header is empty (ref=%s)", tx.Ref().String()))
	})

	t.Run("errors when decryption fails because the key-agreement key could not be found", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.Graph.EXPECT().Get(context.Background(), txOk.Ref()).Return(txOk, nil)
		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return(nil, crypto.ErrKeyNotFound)

		err := proto.handlePrivateTxRetryErr(txOk.Ref())

		assert.EqualError(t, err, fmt.Sprintf("failed to decrypt PAL header (ref=%s): private key of DID keyAgreement not found (kid=%s)", txOk.Ref().String(), keyDID.String()))
	})

	t.Run("valid transaction fails when there is no connection available to the node", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.Graph.EXPECT().Get(context.Background(), txOk.Ref()).Return(txOk, nil)
		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return([]byte(peerDID.String()), nil)
		connectionList := grpc.NewMockConnectionList(mocks.Controller)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*peerDID)).Return(nil)
		proto.connectionList = connectionList

		err := proto.handlePrivateTxRetryErr(txOk.Ref())

		assert.EqualError(t, err, fmt.Sprintf("unable to retrieve payload, no connection found (ref=%s, DID=%s)", txOk.Ref().String(), peerDID.String()))
	})

	t.Run("valid transaction fails when sending the payload query errors", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.Graph.EXPECT().Get(context.Background(), txOk.Ref()).Return(txOk, nil)
		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return([]byte(peerDID.String()), nil)
		conn := grpc.NewMockConnection(mocks.Controller)
		conn.EXPECT().Send(proto, &Envelope{Message: &Envelope_TransactionPayloadQuery{
			TransactionPayloadQuery: &TransactionPayloadQuery{
				TransactionRef: txOk.Ref().Slice(),
			},
		}}).Return(errors.New("random error"))
		connectionList := grpc.NewMockConnectionList(mocks.Controller)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*peerDID)).Return(conn)
		proto.connectionList = connectionList

		err := proto.handlePrivateTxRetryErr(txOk.Ref())

		assert.EqualError(t, err, fmt.Sprintf("failed to send TransactionPayloadQuery message(ref=%s, DID=%s): random error", txOk.Ref().String(), peerDID.String()))
	})

	t.Run("valid transaction is handled successfully", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.Graph.EXPECT().Get(context.Background(), txOk.Ref()).Return(txOk, nil)
		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return([]byte(peerDID.String()), nil)
		conn := grpc.NewMockConnection(mocks.Controller)
		conn.EXPECT().Send(proto, &Envelope{Message: &Envelope_TransactionPayloadQuery{
			TransactionPayloadQuery: &TransactionPayloadQuery{
				TransactionRef: txOk.Ref().Slice(),
			},
		}}).Return(nil)
		connectionList := grpc.NewMockConnectionList(mocks.Controller)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*peerDID)).Return(conn)
		proto.connectionList = connectionList

		err := proto.handlePrivateTxRetryErr(txOk.Ref())

		assert.NoError(t, err)
	})
}

func TestProtocol_decryptPAL(t *testing.T) {
	keyDID, _ := did.ParseDIDURL("did:nuts:123#key1")
	testDID, _ := did.ParseDID("did:nuts:123")
	var emptyPAL [][]byte

	t.Run("errors when node DID is not set", func(t *testing.T) {
		proto, _ := newTestProtocol(t, nil)

		pal, err := proto.decryptPAL(emptyPAL)
		assert.EqualError(t, err, "node DID is not set")
		assert.Nil(t, pal)
	})

	t.Run("errors when resolving the node DID document fails", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)

		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(nil, nil, errors.New("random error"))

		_, err := proto.decryptPAL(emptyPAL)
		assert.EqualError(t, err, "random error")
	})

	t.Run("returns nil for empty PAL", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)

		pal, err := proto.decryptPAL(emptyPAL)

		if !assert.NoError(t, err) {
			return
		}
		assert.Nil(t, pal)
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

		_, err := proto.decryptPAL(tx.PAL())
		assert.EqualError(t, err, fmt.Sprintf("private key of DID keyAgreement not found (kid=%s)", keyDID.String()))
	})

	t.Run("valid transaction is decrypted successfully", func(t *testing.T) {
		tx := dag.CreateSignedTestTransaction(1, time.Now(), [][]byte{{1}, {2}}, "text/plain", true)
		proto, mocks := newTestProtocol(t, testDID)

		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return([]byte(testDID.String()), nil)

		pal, err := proto.decryptPAL(tx.PAL())

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, dag.PAL([]did.DID{*testDID}), pal)
	})
}
