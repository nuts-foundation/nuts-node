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
	PayloadScheduler *MockScheduler
	DocResolver      *vdr.MockDocResolver
	Decrypter        *crypto.MockDecrypter
	Gossip           *gossip.MockManager
	ConnectionList   *grpc.MockConnectionList
}

func newTestProtocol(t *testing.T, nodeDID *did.DID) (*protocol, protocolMocks) {
	ctrl := gomock.NewController(t)
	dirname := io.TestDirectory(t)

	docResolver := vdr.NewMockDocResolver(ctrl)
	decrypter := crypto.NewMockDecrypter(ctrl)
	state := dag.NewMockState(ctrl)
	gMan := gossip.NewMockManager(ctrl)
	payloadScheduler := NewMockScheduler(ctrl)
	connectionList := grpc.NewMockConnectionList(ctrl)
	nodeDIDResolver := transport.FixedNodeDIDResolver{}

	if nodeDID != nil {
		nodeDIDResolver.NodeDID = *nodeDID
	}

	cfg := DefaultConfig()
	cfg.Datadir = dirname
	proto := New(cfg, nodeDIDResolver, state, docResolver, decrypter)
	proto.(*protocol).payloadScheduler = payloadScheduler
	proto.(*protocol).gManager = gMan
	proto.(*protocol).connectionList = connectionList

	return proto.(*protocol), protocolMocks{
		ctrl, state, payloadScheduler, docResolver, decrypter, gMan, connectionList,
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, defaultPayloadRetryDelay, cfg.PayloadRetryDelay)
}

func TestProtocol_Configure(t *testing.T) {
	testDID, _ := did.ParseDID("did:nuts:123")
	p, _ := newTestProtocol(t, testDID)

	assert.NoError(t, p.Configure(""))
}

func TestProtocol_Diagnostics(t *testing.T) {
	failedJobs := []hash.SHA256Hash{[hash.SHA256HashSize]byte{100}}

	proto, mocks := newTestProtocol(t, nil)
	mocks.PayloadScheduler.EXPECT().GetFailedJobs().Return(failedJobs, nil)

	assert.Equal(t, []core.DiagnosticResult{
		&core.GenericDiagnosticResult{
			Title:   "payload_fetch_dlq",
			Outcome: failedJobs,
		},
	}, proto.Diagnostics())
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

		assert.EqualError(t, err, "unable to send msg, connection not found (peer=123@)")
	})
}

func TestProtocol_lifecycle(t *testing.T) {
	ctrl := gomock.NewController(t)

	connectionList := grpc.NewMockConnectionList(ctrl)
	connectionManager := transport.NewMockConnectionManager(ctrl)

	s := grpcLib.NewServer()
	p, mocks := newTestProtocol(t, nil)
	mocks.State.EXPECT().RegisterObserver(gomock.Any(), false)
	mocks.State.EXPECT().Subscribe(dag.TransactionAddedEvent, dag.AnyPayloadType, gomock.Any())
	connectionManager.EXPECT().RegisterObserver(gomock.Any())
	mocks.PayloadScheduler.EXPECT().Run().Return(nil)
	mocks.PayloadScheduler.EXPECT().Close()

	err := p.Start()
	assert.NoError(t, err)

	p.Register(s, func(stream grpcLib.ServerStream) error {
		return nil
	}, connectionList, connectionManager)

	err = p.Handle(transport.Peer{ID: "123"}, &Envelope{})
	assert.EqualError(t, err, "envelope doesn't contain any (handleable) messages")

	p.Stop()
}

func TestProtocol_Start(t *testing.T) {
	t.Run("ok - with node DID", func(t *testing.T) {
		nodeDID, _ := did.ParseDID("did:nuts:123")
		proto, mocks := newTestProtocol(t, nodeDID)

		mocks.PayloadScheduler.EXPECT().Run().Return(nil)
		mocks.PayloadScheduler.EXPECT().Close()
		mocks.State.EXPECT().RegisterObserver(gomock.Any(), false)
		mocks.State.EXPECT().Subscribe(dag.TransactionAddedEvent, dag.AnyPayloadType, gomock.Any())

		err := proto.Start()
		assert.NoError(t, err)

		proto.Stop()

		time.Sleep(2 * time.Second)
	})

	t.Run("ok - without node DID", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)

		mocks.PayloadScheduler.EXPECT().Close()

		err := proto.Start()
		assert.NoError(t, err)

		proto.Stop()

		time.Sleep(2 * time.Second)
	})
}

func TestProtocol_connectionStateCallback(t *testing.T) {
	t.Run("ok - connected", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.Gossip.EXPECT().PeerConnected(peer)

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

func TestProtocol_sendGossip(t *testing.T) {
	peerID := transport.PeerID("1")
	refsAsBytes := [][]byte{hash.EmptyHash().Slice()}

	t.Run("ok", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mockConnection := grpc.NewMockConnection(mocks.Controller)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peerID)).Return(mockConnection)
		mockConnection.EXPECT().Send(proto, &Envelope{Message: &Envelope_Gossip{
			Gossip: &Gossip{
				Transactions: refsAsBytes,
			},
		}})

		success := proto.sendGossip(peerID, []hash.SHA256Hash{hash.EmptyHash()})

		assert.True(t, success)
	})
	t.Run("error - no connection available", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peerID)).Return(nil)

		success := proto.sendGossip(peerID, []hash.SHA256Hash{hash.EmptyHash()})

		assert.False(t, success)
	})
}

func TestProtocol_gossipTransaction(t *testing.T) {
	t.Run("ok - no transaction", func(t *testing.T) {
		proto, _ := newTestProtocol(t, nil)

		proto.gossipTransaction(context.Background(), nil, nil)
	})

	t.Run("ok - to gossipManager", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		tx, _, _ := dag.CreateTestTransaction(0)
		mocks.Gossip.EXPECT().TransactionRegistered(tx.Ref())

		proto.gossipTransaction(context.Background(), tx, nil)
	})
}

func TestProtocol_HandlePrivateTx(t *testing.T) {
	txOk := dag.CreateSignedTestTransaction(1, time.Now(), [][]byte{{1}, {2}}, "text/plain", true)

	t.Run("ok - event passed as job to payloadScheduler", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.PayloadScheduler.EXPECT().Schedule(txOk.Ref())

		err := proto.handlePrivateTx(txOk, nil)

		assert.NoError(t, err)
	})

	t.Run("ok - event ignored", func(t *testing.T) {
		tx, _, _ := dag.CreateTestTransaction(0)
		proto, _ := newTestProtocol(t, nil)

		err := proto.handlePrivateTx(tx, nil)

		assert.NoError(t, err)
	})

	t.Run("ok - event ignored because of non-empty payload", func(t *testing.T) {
		tx, _, _ := dag.CreateTestTransaction(0)
		proto, _ := newTestProtocol(t, nil)

		err := proto.handlePrivateTx(tx, []byte{0})

		assert.NoError(t, err)
	})

	t.Run("error - can't add to scheduler", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.PayloadScheduler.EXPECT().Schedule(txOk.Ref()).Return(errors.New("b00m!"))

		err := proto.handlePrivateTx(txOk, nil)

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
	txOk := dag.CreateSignedTestTransaction(1, time.Now(), [][]byte{{1}, {2}}, "text/plain", true)

	t.Run("errors when retrieving transaction errors", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)

		mocks.State.EXPECT().GetTransaction(context.Background(), txOk.Ref()).Return(nil, errors.New("random error"))

		err := proto.handlePrivateTxRetryErr(txOk.Ref())
		assert.EqualError(t, err, fmt.Sprintf("failed to retrieve transaction (tx=:%s) from the DAG: %s", txOk.Ref().String(), "random error"))
	})

	t.Run("errors when transaction could not be found", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)

		mocks.State.EXPECT().GetTransaction(context.Background(), txOk.Ref()).Return(nil, nil)

		err := proto.handlePrivateTxRetryErr(txOk.Ref())
		assert.EqualError(t, err, fmt.Sprintf("failed to find transaction (tx=:%s) in DAG", txOk.Ref().String()))
	})

	t.Run("errors when reading payload errors", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)

		mocks.State.EXPECT().ReadPayload(gomock.Any(), txOk.PayloadHash()).Return(nil, errors.New("random error"))
		mocks.State.EXPECT().GetTransaction(context.Background(), txOk.Ref()).Return(txOk, nil)

		err := proto.handlePrivateTxRetryErr(txOk.Ref())
		assert.EqualError(t, err, fmt.Sprintf("unable to read payload (tx=%s): random error", txOk.Ref().String()))
	})

	t.Run("Finishes job when payload is already there", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)

		mocks.State.EXPECT().ReadPayload(gomock.Any(), txOk.PayloadHash()).Return([]byte{0}, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), txOk.Ref()).Return(txOk, nil)
		mocks.PayloadScheduler.EXPECT().Finished(txOk.Ref())

		err := proto.handlePrivateTxRetryErr(txOk.Ref())

		assert.NoError(t, err)
	})

	t.Run("removes scheduled job when payload is present", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().ReadPayload(context.Background(), txOk.PayloadHash()).Return([]byte{}, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), txOk.Ref()).Return(txOk, nil)
		mocks.PayloadScheduler.EXPECT().Finished(txOk.Ref())

		err := proto.handlePrivateTxRetryErr(txOk.Ref())

		assert.NoError(t, err)
	})

	t.Run("errors when node DID is not set", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().ReadPayload(context.Background(), txOk.PayloadHash()).Return(nil, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), txOk.Ref()).Return(txOk, nil)

		err := proto.handlePrivateTxRetryErr(txOk.Ref())
		assert.EqualError(t, err, fmt.Sprintf("failed to decrypt PAL header (tx=%s): node DID is not set", txOk.Ref()))
	})

	t.Run("errors when resolving the node DID document fails", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.State.EXPECT().GetTransaction(context.Background(), txOk.Ref()).Return(txOk, nil)
		mocks.State.EXPECT().ReadPayload(context.Background(), txOk.PayloadHash()).Return(nil, nil)
		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(nil, nil, errors.New("random error"))

		err := proto.handlePrivateTxRetryErr(txOk.Ref())

		assert.EqualError(t, err, fmt.Sprintf("failed to decrypt PAL header (tx=%s): random error", txOk.Ref()))
	})

	t.Run("removes job when the transaction doesn't contain a valid PAL header", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		txOk := dag.CreateSignedTestTransaction(1, time.Now(), nil, "text/plain", true)

		mocks.State.EXPECT().ReadPayload(gomock.Any(), txOk.PayloadHash()).Return(nil, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), txOk.Ref()).Return(txOk, nil)
		mocks.PayloadScheduler.EXPECT().Finished(txOk.Ref())

		err := proto.handlePrivateTxRetryErr(txOk.Ref())
		assert.NoError(t, err)
	})

	t.Run("errors when decryption fails because the key-agreement key could not be found", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)

		mocks.State.EXPECT().GetTransaction(context.Background(), txOk.Ref()).Return(txOk, nil)
		mocks.State.EXPECT().ReadPayload(context.Background(), txOk.PayloadHash()).Return(nil, nil)
		mocks.DocResolver.EXPECT().Resolve(*testDID, nil).Return(&did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}, nil, nil)
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return(nil, crypto.ErrKeyNotFound)

		err := proto.handlePrivateTxRetryErr(txOk.Ref())

		assert.EqualError(t, err, fmt.Sprintf("failed to decrypt PAL header (tx=%s): private key of DID keyAgreement not found (kid=%s)", txOk.Ref().String(), keyDID.String()))
	})

	t.Run("valid transaction fails when there is no connection available to the node", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.State.EXPECT().ReadPayload(context.Background(), txOk.PayloadHash()).Return(nil, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), txOk.Ref()).Return(txOk, nil)
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

		assert.EqualError(t, err, fmt.Sprintf("no connection to any of the participants (tx=%s, PAL=[did:nuts:peer])", txOk.Ref().String()))
	})

	t.Run("valid transaction fails when sending the payload query errors", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.State.EXPECT().ReadPayload(context.Background(), txOk.PayloadHash()).Return(nil, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), txOk.Ref()).Return(txOk, nil)
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

		assert.EqualError(t, err, fmt.Sprintf("no connection to any of the participants (tx=%s, PAL=[did:nuts:peer])", txOk.Ref().String()))
	})

	t.Run("valid transaction is handled successfully", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, testDID)
		mocks.State.EXPECT().ReadPayload(context.Background(), txOk.PayloadHash()).Return(nil, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), txOk.Ref()).Return(txOk, nil)
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
	t.Run("broadcasts to all participants (except local node)", func(t *testing.T) {
		tx := dag.CreateSignedTestTransaction(1, time.Now(), [][]byte{{1}, {2}, {3}}, "text/plain", true)

		proto, mocks := newTestProtocol(t, testDID)

		mocks.State.EXPECT().ReadPayload(gomock.Any(), tx.PayloadHash()).Return(nil, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), tx.Ref()).Return(tx, nil)
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
		}}).Return(nil)
		// Connection to other peer
		conn2 := grpc.NewMockConnection(mocks.Controller)
		conn2.EXPECT().Send(proto, &Envelope{Message: &Envelope_TransactionPayloadQuery{
			TransactionPayloadQuery: &TransactionPayloadQuery{
				TransactionRef: tx.Ref().Slice(),
			},
		}}).Return(nil)
		connectionList := grpc.NewMockConnectionList(mocks.Controller)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*nodeDID)).Return(nil)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*peerDID)).Return(conn1)
		connectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByNodeDID(*otherPeerDID)).Return(conn2)
		proto.connectionList = connectionList

		err := proto.handlePrivateTxRetryErr(tx.Ref())

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
		mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), []byte{1}).Return(append(append([]byte(testDID.String()), '\n'), []byte(testDID2.String())...), nil)

		pal, err := proto.decryptPAL(tx.PAL())

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, dag.PAL([]did.DID{*testDID, *testDID2}), pal)
	})
}
