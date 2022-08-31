/*
 * Copyright (C) 2022 Nuts community
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

package v2

import (
	"context"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-stoabs"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network/transport/v2/gossip"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	grpcLib "google.golang.org/grpc"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

type protocolMocks struct {
	Controller       *gomock.Controller
	State            *dag.MockState
	PayloadScheduler *dag.MockNotifier
	DocResolver      *vdr.MockDocResolver
	Decrypter        *crypto.MockDecrypter
	Gossip           *gossip.MockManager
	ConnectionList   *grpc.MockConnectionList
	Sender           *MockmessageSender
	DagStore         *stoabs.MockKVStore
}

func getMessageTypes() []isEnvelope_Message {
	// Magic const 0 is the first message in the protobuf definition
	msgs := file_transport_v2_protocol_proto_msgTypes[0].OneofWrappers
	var result []isEnvelope_Message
	for _, msg := range msgs {
		result = append(result, msg.(isEnvelope_Message))
	}
	if len(result) == 0 {
		// Just so the tests break when the protobuf definition changes
		panic("expected one-of in first protobuf message")
	}
	return result
}

func newTestProtocol(t *testing.T, nodeDID *did.DID) (*protocol, protocolMocks) {
	ctrl := gomock.NewController(t)
	dirname := io.TestDirectory(t)

	docResolver := vdr.NewMockDocResolver(ctrl)
	decrypter := crypto.NewMockDecrypter(ctrl)
	state := dag.NewMockState(ctrl)
	gMan := gossip.NewMockManager(ctrl)
	payloadScheduler := dag.NewMockNotifier(ctrl)
	connectionList := grpc.NewMockConnectionList(ctrl)
	sender := NewMockmessageSender(ctrl)
	nodeDIDResolver := transport.FixedNodeDIDResolver{}
	storage := stoabs.NewMockKVStore(ctrl)

	if nodeDID != nil {
		nodeDIDResolver.NodeDID = *nodeDID
	}

	cfg := DefaultConfig()
	cfg.Datadir = dirname
	proto := New(cfg, nodeDIDResolver, state, docResolver, decrypter, nil, storage).(*protocol)
	proto.privatePayloadReceiver = payloadScheduler
	proto.gManager = gMan
	proto.cMan = newConversationManager(time.Second)
	proto.connectionList = connectionList
	proto.sender = sender
	proto.listHandler = newTransactionListHandler(context.Background(), proto.handleTransactionList)

	return proto, protocolMocks{
		Controller:       ctrl,
		State:            state,
		PayloadScheduler: payloadScheduler,
		DocResolver:      docResolver,
		Decrypter:        decrypter,
		Gossip:           gMan,
		ConnectionList:   connectionList,
		Sender:           sender,
		DagStore:         storage,
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, defaultPayloadRetryDelay, cfg.PayloadRetryDelay)
}

func TestProtocol_Configure(t *testing.T) {
	testDID, _ := did.ParseDID("did:nuts:123")
	p, mocks := newTestProtocol(t, testDID)
	mocks.State.EXPECT().Notifier("private", gomock.Any(), gomock.Len(3))
	mocks.State.EXPECT().Notifier("gossip", gomock.Any(), gomock.Len(2))

	assert.NoError(t, p.Configure(""))
}

func TestProtocol_Diagnostics(t *testing.T) {
	failedJobs := []dag.Event{{}}

	proto, mocks := newTestProtocol(t, nil)
	mocks.PayloadScheduler.EXPECT().GetFailedEvents().Return(failedJobs, nil)

	assert.Equal(t, []core.DiagnosticResult{
		&core.GenericDiagnosticResult{
			Title:   "payload_fetch_dlq",
			Outcome: failedJobs,
		},
	}, proto.Diagnostics())
}

func TestProtocol_PeerDiagnostics(t *testing.T) {
	mgr := newPeerDiagnosticsManager(nil, nil)
	expected := map[transport.PeerID]transport.Diagnostics{
		transport.PeerID("1234"): {SoftwareID: "4321", Peers: []transport.PeerID{}},
	}
	mgr.received = expected
	assert.Equal(t, expected, protocol{diagnosticsMan: mgr}.PeerDiagnostics())
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
		connection.EXPECT().Send(p, &Envelope{Message: msg}, false)

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

		assert.EqualError(t, err, "unable to send msg, connection not found (peer=123@)")
	})
}

func TestProtocol_lifecycle(t *testing.T) {
	ctrl := gomock.NewController(t)

	connectionList := grpc.NewMockConnectionList(ctrl)
	connectionManager := transport.NewMockConnectionManager(ctrl)

	s := grpcLib.NewServer()
	p, _ := newTestProtocol(t, nil)
	connectionManager.EXPECT().RegisterObserver(gomock.Any())

	err := p.Start()
	assert.NoError(t, err)

	p.Register(s, func(stream grpcLib.ServerStream) error {
		return nil
	}, connectionList, connectionManager)

	err = p.Handle(transport.Peer{ID: "123"}, &Envelope{})
	assert.Equal(t, errMessageNotSupported, err)

	p.Stop()
}

func TestProtocol_Start(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		proto, _ := newTestProtocol(t, nodeDID)

		err := proto.Start()
		assert.NoError(t, err)

		proto.Stop()
	})
}

func TestProtocol_connectionStateCallback(t *testing.T) {
	t.Run("ok - connected", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(gomock.Any(), uint32(dag.MaxLamportClock)).Return(hash.EmptyHash(), uint32(5))
		mocks.Gossip.EXPECT().PeerConnected(peer, hash.EmptyHash(), uint32(5))

		proto.connectionStateCallback(peer, transport.StateConnected, proto)
	})

	t.Run("ok - disconnected", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)

		mocks.Gossip.EXPECT().PeerDisconnected(peer)

		proto.connectionStateCallback(peer, transport.StateDisconnected, proto)
	})

	t.Run("ok - ignored streams from other protocols", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mockProto := transport.NewMockProtocol(mocks.Controller)
		mockProto.EXPECT().Version().Return(0)

		proto.connectionStateCallback(peer, transport.StateConnected, mockProto)
	})
}

func TestProtocol_gossipTransaction(t *testing.T) {
	t.Run("ok - to gossipManager", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		tx, _, _ := dag.CreateTestTransaction(0)
		mocks.State.EXPECT().XOR(gomock.Any(), uint32(dag.MaxLamportClock))
		mocks.Gossip.EXPECT().TransactionRegistered(tx.Ref(), hash.EmptyHash(), uint32(0))
		event := dag.Event{
			Type:        dag.TransactionEventType,
			Hash:        tx.Ref(),
			Retries:     0,
			Transaction: tx,
			Payload:     nil,
		}

		proto.gossipTransaction(event)
	})
}

//nolint:funlen
func TestProtocol_HandlePrivateTxRetry(t *testing.T) {
	keyDID, _ := did.ParseDIDURL("did:nuts:123#key1")
	testDID, _ := did.ParseDID("did:nuts:123")
	txOk := dag.CreateSignedTestTransaction(1, time.Now(), [][]byte{{1}, {2}}, "text/plain", true)
	event := dag.Event{
		Type:        dag.TransactionEventType,
		Hash:        txOk.Ref(),
		Retries:     0,
		Transaction: txOk,
	}

	t.Run("errors when reading payload errors", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)

		mocks.State.EXPECT().ReadPayload(gomock.Any(), txOk.PayloadHash()).Return(nil, errors.New("random error"))

		finished, err := proto.handlePrivateTxRetry(event)

		assert.False(t, finished)
		assert.EqualError(t, err, fmt.Sprintf("unable to read payload (tx=%s): random error", txOk.Ref().String()))
	})

	t.Run("Finishes job when payload is already there", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)

		mocks.State.EXPECT().ReadPayload(gomock.Any(), txOk.PayloadHash()).Return([]byte{0}, nil)

		finished, err := proto.handlePrivateTxRetry(event)

		assert.True(t, finished)
		assert.NoError(t, err)
	})

	t.Run("removes scheduled job when payload is present", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().ReadPayload(context.Background(), txOk.PayloadHash()).Return([]byte{}, nil)

		finished, err := proto.handlePrivateTxRetry(event)

		assert.True(t, finished)
		assert.NoError(t, err)
	})

	t.Run("errors when node DID is not set", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().ReadPayload(context.Background(), txOk.PayloadHash()).Return(nil, nil)

		finished, err := proto.handlePrivateTxRetry(event)

		assert.False(t, finished)
		assert.EqualError(t, err, fmt.Sprintf("failed to decrypt PAL header (tx=%s): node DID is not set", txOk.Ref()))
	})

	t.Run("errors when resolving the node DID document fails", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.State.EXPECT().ReadPayload(context.Background(), txOk.PayloadHash()).Return(nil, nil)
		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(nil, nil, errors.New("random error"))

		finished, err := proto.handlePrivateTxRetry(event)

		assert.False(t, finished)
		assert.EqualError(t, err, fmt.Sprintf("failed to decrypt PAL header (tx=%s): random error", txOk.Ref()))
	})

	t.Run("errors when decryption fails because the key-agreement key could not be found", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)

		mocks.State.EXPECT().ReadPayload(context.Background(), txOk.PayloadHash()).Return(nil, nil)
		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return(nil, crypto.ErrPrivateKeyNotFound)

		finished, err := proto.handlePrivateTxRetry(event)

		assert.False(t, finished)
		assert.EqualError(t, err, fmt.Sprintf("failed to decrypt PAL header (tx=%s): private key of DID keyAgreement not found (kid=%s)", txOk.Ref().String(), keyDID.String()))
	})

	t.Run("valid transaction fails when there is no connection available to the node", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.State.EXPECT().ReadPayload(context.Background(), txOk.PayloadHash()).Return(nil, nil)
		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return([]byte(peerDID.String()), nil)
		connectionList := grpc.NewMockConnectionList(mocks.Controller)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*peerDID)).Return(nil)
		proto.connectionList = connectionList

		finished, err := proto.handlePrivateTxRetry(event)

		assert.False(t, finished)
		assert.EqualError(t, err, fmt.Sprintf("no connection to any of the participants (tx=%s, PAL=[did:nuts:peer])", txOk.Ref().String()))
	})

	t.Run("valid transaction fails when sending the payload query errors", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.State.EXPECT().ReadPayload(context.Background(), txOk.PayloadHash()).Return(nil, nil)
		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return([]byte(peerDID.String()), nil)
		conn := grpc.NewMockConnection(mocks.Controller)
		conn.EXPECT().Peer()
		conn.EXPECT().Send(proto, &Envelope{Message: &Envelope_TransactionPayloadQuery{
			TransactionPayloadQuery: &TransactionPayloadQuery{
				TransactionRef: txOk.Ref().Slice(),
			},
		}}, false).Return(errors.New("random error"))
		connectionList := grpc.NewMockConnectionList(mocks.Controller)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*peerDID)).Return(conn)
		proto.connectionList = connectionList

		finished, err := proto.handlePrivateTxRetry(event)

		assert.False(t, finished)
		assert.EqualError(t, err, fmt.Sprintf("no connection to any of the participants (tx=%s, PAL=[did:nuts:peer])", txOk.Ref().String()))
	})

	t.Run("valid transaction is handled successfully", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.State.EXPECT().ReadPayload(context.Background(), txOk.PayloadHash()).Return(nil, nil)
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
		}}, false).Return(nil)
		connectionList := grpc.NewMockConnectionList(mocks.Controller)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*peerDID)).Return(conn)
		proto.connectionList = connectionList

		finished, err := proto.handlePrivateTxRetry(event)

		// Finished is called when Payload is received nto when the request is sent
		assert.False(t, finished)
		assert.NoError(t, err)
	})
	t.Run("broadcasts to all participants (except local node)", func(t *testing.T) {
		tx := dag.CreateSignedTestTransaction(1, time.Now(), [][]byte{{1}, {2}, {3}}, "text/plain", true)
		event := dag.Event{
			Type:        dag.TransactionEventType,
			Hash:        tx.Ref(),
			Retries:     0,
			Transaction: txOk,
		}

		proto, mocks := newTestProtocol(t, testDID)

		mocks.State.EXPECT().ReadPayload(gomock.Any(), tx.PayloadHash()).Return(nil, nil)
		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		encodedPAL := strings.Join([]string{nodeDID.String(), peerDID.String(), otherPeerDID.String()}, "\n")
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return([]byte(encodedPAL), nil)
		// Connection to peer
		conn1 := grpc.NewMockConnection(mocks.Controller)
		conn1.EXPECT().Send(proto, &Envelope{Message: &Envelope_TransactionPayloadQuery{
			TransactionPayloadQuery: &TransactionPayloadQuery{
				TransactionRef: tx.Ref().Slice(),
			},
		}}, false).Return(nil)
		// Connection to other peer
		conn2 := grpc.NewMockConnection(mocks.Controller)
		conn2.EXPECT().Send(proto, &Envelope{Message: &Envelope_TransactionPayloadQuery{
			TransactionPayloadQuery: &TransactionPayloadQuery{
				TransactionRef: tx.Ref().Slice(),
			},
		}}, false).Return(nil)
		connectionList := grpc.NewMockConnectionList(mocks.Controller)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*nodeDID)).Return(nil)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*peerDID)).Return(conn1)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*otherPeerDID)).Return(conn2)
		proto.connectionList = connectionList

		finished, err := proto.handlePrivateTxRetry(event)

		// only on receiving payload
		assert.False(t, finished)
		assert.NoError(t, err)
	})
}

func TestProtocol_decryptPAL(t *testing.T) {
	keyDID, _ := did.ParseDIDURL("did:nuts:123#key1")
	testDID, _ := did.ParseDID("did:nuts:123")
	testDID2, _ := did.ParseDID("did:nuts:456")
	dummyPAL := [][]byte{{0}}

	t.Run("errors when node DID is not set", func(t *testing.T) {
		proto, _ := newTestProtocol(t, nil)

		pal, err := proto.decryptPAL(dummyPAL)
		assert.EqualError(t, err, "node DID is not set")
		assert.Nil(t, pal)
	})

	t.Run("errors when resolving the node DID document fails", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)

		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(nil, nil, errors.New("random error"))

		_, err := proto.decryptPAL(dummyPAL)
		assert.EqualError(t, err, "random error")
	})

	t.Run("returns nil for empty PAL", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)

		pal, err := proto.decryptPAL([][]byte{})

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
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return(nil, crypto.ErrPrivateKeyNotFound)

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
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return(append(append([]byte(testDID.String()), '\n'), []byte(testDID2.String())...), nil)

		pal, err := proto.decryptPAL(tx.PAL())

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, dag.PAL([]did.DID{*testDID, *testDID2}), pal)
	})
}

func Test_protocol_GetMessageType(t *testing.T) {
	p := &protocol{}
	t.Run("known case", func(t *testing.T) {
		actual := p.GetMessageType(&Envelope{Message: &Envelope_Gossip{}})
		assert.Equal(t, "Gossip", actual)
	})
	t.Run("all message types are handled", func(t *testing.T) {
		for _, msg := range getMessageTypes() {
			actual := p.GetMessageType(&Envelope{Message: msg})
			assert.NotEqual(t, "unknown", actual)
		}
	})
	t.Run("unknown msg", func(t *testing.T) {
		actual := p.GetMessageType("not an envelope")
		assert.Equal(t, "unknown", actual)
	})
}
