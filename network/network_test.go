/*
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

package network

import (
	"errors"
	p2p2 "github.com/nuts-foundation/nuts-node/network/protocol/v1/p2p"
	"github.com/nuts-foundation/nuts-node/network/protocol/v1/proto"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
)

type networkTestContext struct {
	network     *Network
	p2pAdapter  *p2p2.MockAdapter
	protocol    *proto.MockProtocol
	graph       *dag.MockDAG
	payload     *dag.MockPayloadStore
	keyStore    *crypto.MockKeyStore
	publisher   *dag.MockPublisher
	keyResolver *types.MockKeyResolver
}

func TestNetwork_ListTransactions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(ctrl)
		cxt.graph.EXPECT().FindBetween(gomock.Any(), gomock.Any(), gomock.Any()).Return([]dag.Transaction{dag.CreateTestTransactionWithJWK(1)}, nil)
		docs, err := cxt.network.ListTransactions()
		assert.Len(t, docs, 1)
		assert.NoError(t, err)
	})
}

func TestNetwork_Name(t *testing.T) {
	assert.Equal(t, "Network", (&Network{}).Name())
}

func TestNetwork_Config(t *testing.T) {
	n := &Network{}
	assert.Same(t, &n.config, n.Config())
}

func TestNetwork_GetTransaction(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(ctrl)
		cxt.graph.EXPECT().Get(gomock.Any(), gomock.Any())
		cxt.network.GetTransaction(hash.EmptyHash())
	})
}

func TestNetwork_GetTransactionPayload(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(ctrl)
		transaction := dag.CreateTestTransactionWithJWK(1)
		cxt.graph.EXPECT().Get(gomock.Any(), transaction.Ref()).Return(transaction, nil)
		cxt.payload.EXPECT().ReadPayload(gomock.Any(), transaction.PayloadHash())
		cxt.network.GetTransactionPayload(transaction.Ref())
	})
	t.Run("ok - TX not found", func(t *testing.T) {
		cxt := createNetwork(ctrl)
		transaction := dag.CreateTestTransactionWithJWK(1)
		cxt.graph.EXPECT().Get(gomock.Any(), transaction.Ref()).Return(nil, nil)
		payload, err := cxt.network.GetTransactionPayload(transaction.Ref())
		assert.NoError(t, err)
		assert.Nil(t, payload)
	})
}

func TestNetwork_Subscribe(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(ctrl)
		cxt.publisher.EXPECT().Subscribe("some-type", nil)
		cxt.network.Subscribe("some-type", nil)
	})
}

func TestNetwork_Diagnostics(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(ctrl)
		cxt.protocol.EXPECT().Diagnostics().Return([]core.DiagnosticResult{stat{}, stat{}})
		cxt.p2pAdapter.EXPECT().Diagnostics().Return([]core.DiagnosticResult{stat{}, stat{}})
		diagnostics := cxt.network.Diagnostics()
		assert.Len(t, diagnostics, 4)
	})
}

func TestNetwork_Configure(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.protocol.EXPECT().Configure(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		cxt.p2pAdapter.EXPECT().Configure(gomock.Any())
		err := cxt.network.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
		if !assert.NoError(t, err) {
			return
		}
	})
	t.Run("certs not configured (offline mode)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.protocol.EXPECT().Configure(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		cxt.network.config.CertKeyFile = ""
		cxt.network.config.CertFile = ""
		err := cxt.network.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
		if !assert.NoError(t, err) {
			return
		}
	})
	t.Run("truststore not configured (offline mode)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.protocol.EXPECT().Configure(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		cxt.network.config.TrustStoreFile = ""
		err := cxt.network.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
		if !assert.NoError(t, err) {
			return
		}
	})
	t.Run("disable TLS for incoming connections (SSL offloading)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.protocol.EXPECT().Configure(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		cxt.p2pAdapter.EXPECT().Configure(gomock.Any())
		cxt.network.config.TrustStoreFile = ""
		cxt.network.config.EnableTLS = false
		err := cxt.network.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
		if !assert.NoError(t, err) {
			return
		}
	})
	t.Run("unable to create datadir", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		err := cxt.network.Configure(core.ServerConfig{Datadir: "network_test.go"})
		assert.Error(t, err)
	})
}

func TestNetwork_CreateTransaction(t *testing.T) {
	key := crypto.NewTestKey("signing-key")
	t.Run("ok - attach key", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		payload := []byte("Hello, World!")
		cxt := createNetwork(ctrl)
		cxt.p2pAdapter.EXPECT().Start()
		cxt.p2pAdapter.EXPECT().Configured().Return(true)
		cxt.protocol.EXPECT().Start()
		cxt.graph.EXPECT().Verify(gomock.Any())
		cxt.graph.EXPECT().Add(gomock.Any(), gomock.Any())
		cxt.payload.EXPECT().WritePayload(gomock.Any(), hash.SHA256Sum(payload), payload)

		cxt.publisher.EXPECT().Subscribe(dag.AnyPayloadType, gomock.Any()) // head-with-payload tracking subscriber
		cxt.publisher.EXPECT().Start()
		err := cxt.network.Start()
		if !assert.NoError(t, err) {
			return
		}
		_, err = cxt.network.CreateTransaction(payloadType, payload, key, true, time.Now(), []hash.SHA256Hash{})
		assert.NoError(t, err)
	})
	t.Run("ok - detached key", func(t *testing.T) {
		payload := []byte("Hello, World!")
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.p2pAdapter.EXPECT().Start()
		cxt.p2pAdapter.EXPECT().Configured().Return(true)
		cxt.protocol.EXPECT().Start()
		cxt.graph.EXPECT().Verify(gomock.Any())
		cxt.graph.EXPECT().Add(gomock.Any(), gomock.Any())
		cxt.payload.EXPECT().WritePayload(gomock.Any(), hash.SHA256Sum(payload), payload)
		cxt.publisher.EXPECT().Subscribe(dag.AnyPayloadType, gomock.Any()) // head-with-payload tracking subscriber
		cxt.publisher.EXPECT().Start()
		err := cxt.network.Start()
		if !assert.NoError(t, err) {
			return
		}
		tx, err := cxt.network.CreateTransaction(payloadType, payload, key, false, time.Now(), []hash.SHA256Hash{})
		assert.NoError(t, err)
		assert.Len(t, tx.Previous(), 0)
	})
	t.Run("ok - additional prevs", func(t *testing.T) {
		payload := []byte("Hello, World!")
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.p2pAdapter.EXPECT().Start()
		cxt.p2pAdapter.EXPECT().Configured().Return(true)
		cxt.protocol.EXPECT().Start()
		cxt.graph.EXPECT().Verify(gomock.Any())

		// Register root TX on head tracker
		rootTX, _, _ := dag.CreateTestTransaction(0)
		cxt.network.lastTransactionTracker.process(rootTX, []byte{1, 2, 3})

		// 'Register' prev on DAG
		additionalPrev, _, _ := dag.CreateTestTransaction(1)
		cxt.graph.EXPECT().Get(gomock.Any(), additionalPrev.Ref()).Return(additionalPrev, nil)
		cxt.payload.EXPECT().IsPresent(gomock.Any(), additionalPrev.PayloadHash()).Return(true, nil)

		cxt.graph.EXPECT().Add(gomock.Any(), gomock.Any())
		cxt.payload.EXPECT().WritePayload(gomock.Any(), hash.SHA256Sum(payload), payload)
		cxt.publisher.EXPECT().Subscribe(dag.AnyPayloadType, gomock.Any()) // head-with-payload tracking subscriber
		cxt.publisher.EXPECT().Start()
		err := cxt.network.Start()
		if !assert.NoError(t, err) {
			return
		}
		tx, err := cxt.network.CreateTransaction(payloadType, payload, key, false, time.Now(), []hash.SHA256Hash{additionalPrev.Ref()})

		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, tx.Previous(), 2)
		assert.Equal(t, rootTX.Ref(), tx.Previous()[0])
		assert.Equal(t, additionalPrev.Ref(), tx.Previous()[1])
	})
	t.Run("error - additional prev is missing payload", func(t *testing.T) {
		payload := []byte("Hello, World!")
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.p2pAdapter.EXPECT().Start()
		cxt.p2pAdapter.EXPECT().Configured().Return(true)
		cxt.protocol.EXPECT().Start()
		cxt.graph.EXPECT().Verify(gomock.Any())
		cxt.publisher.EXPECT().Subscribe(dag.AnyPayloadType, gomock.Any()) // head-with-payload tracking subscriber
		cxt.publisher.EXPECT().Start()
		err := cxt.network.Start()
		if !assert.NoError(t, err) {
			return
		}

		// 'Register' prev on DAG
		prev, _, _ := dag.CreateTestTransaction(1)
		cxt.graph.EXPECT().Get(gomock.Any(), prev.Ref()).Return(prev, nil)
		cxt.payload.EXPECT().IsPresent(gomock.Any(), prev.PayloadHash()).Return(false, nil)

		tx, err := cxt.network.CreateTransaction(payloadType, payload, key, false, time.Now(), []hash.SHA256Hash{prev.Ref()})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "additional prev is unknown or missing payload")
		assert.Nil(t, tx)
	})
}

func TestNetwork_Start(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.p2pAdapter.EXPECT().Start()
		cxt.p2pAdapter.EXPECT().Configured().Return(true)
		cxt.protocol.EXPECT().Start()
		cxt.graph.EXPECT().Verify(gomock.Any())
		cxt.publisher.EXPECT().Subscribe(dag.AnyPayloadType, gomock.Any()) // head-with-payload tracking subscriber
		cxt.publisher.EXPECT().Start()
		err := cxt.network.Start()
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, cxt.network.startTime.Load())
	})
	t.Run("ok - offline", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.p2pAdapter.EXPECT().Configured().Return(false)
		cxt.protocol.EXPECT().Start()
		cxt.graph.EXPECT().Verify(gomock.Any())
		cxt.publisher.EXPECT().Subscribe(dag.AnyPayloadType, gomock.Any()) // head-with-payload tracking subscriber
		cxt.publisher.EXPECT().Start()
		err := cxt.network.Start()
		if !assert.NoError(t, err) {
			return
		}
	})
	t.Run("error - DAG verification failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.p2pAdapter.EXPECT().Configured().Return(false)
		cxt.protocol.EXPECT().Start()
		cxt.graph.EXPECT().Verify(gomock.Any()).Return(errors.New("failed"))
		cxt.publisher.EXPECT().Subscribe(dag.AnyPayloadType, gomock.Any()) // head-with-payload tracking subscriber
		cxt.publisher.EXPECT().Start()
		err := cxt.network.Start()
		assert.EqualError(t, err, "failed")
	})
}

func TestNetwork_Shutdown(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.p2pAdapter.EXPECT().Stop()
		err := cxt.network.Shutdown()
		assert.NoError(t, err)
	})
	t.Run("error - stop returns error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.p2pAdapter.EXPECT().Stop().Return(errors.New("failed"))
		err := cxt.network.Shutdown()
		assert.EqualError(t, err, "failed")
	})
}

func TestNetwork_collectDiagnostics(t *testing.T) {
	const txNum = 5
	const expectedVersion = "0"
	const expectedID = "https://github.com/nuts-foundation/nuts-node"
	expectedPeer := p2p2.Peer{ID: "abc", Address: "123"}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cxt := createNetwork(ctrl)
	cxt.graph.EXPECT().Statistics(gomock.Any()).Return(dag.Statistics{NumberOfTransactions: txNum})

	cxt.p2pAdapter.EXPECT().Peers().Return([]p2p2.Peer{expectedPeer})

	actual := cxt.network.collectDiagnostics()

	assert.Equal(t, expectedID, actual.SoftwareID)
	assert.Equal(t, expectedVersion, actual.SoftwareVersion)
	assert.Equal(t, []p2p2.PeerID{expectedPeer.ID}, actual.Peers)
	assert.Equal(t, uint32(txNum), actual.NumberOfTransactions)
	assert.NotEmpty(t, actual.Uptime)
}

func TestNetwork_buildP2PNetworkConfig(t *testing.T) {
	t.Run("ok - TLS enabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.network.config.GrpcAddr = ":5555"
		cxt.network.config.EnableTLS = true
		cxt.network.config.CertFile = "test/certificate-and-key.pem"
		cxt.network.config.CertKeyFile = "test/certificate-and-key.pem"
		cfg, err := cxt.network.buildP2PConfig("")
		assert.NotNil(t, cfg)
		assert.NoError(t, err)
		assert.NotNil(t, cfg.ClientCert.PrivateKey)
		assert.NotNil(t, cfg.ServerCert.PrivateKey)
	})
	t.Run("ok - TLS disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.network.config.GrpcAddr = ":5555"
		cxt.network.config.EnableTLS = false
		cfg, err := cxt.network.buildP2PConfig("")
		assert.NotNil(t, cfg)
		assert.NoError(t, err)
		assert.Nil(t, cfg.ClientCert.PrivateKey)
		assert.Nil(t, cfg.ServerCert.PrivateKey)
	})
	t.Run("ok - gRPC server not bound", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.network.config.GrpcAddr = ""
		cxt.network.config.EnableTLS = true
		cfg, err := cxt.network.buildP2PConfig("")
		assert.NotNil(t, cfg)
		assert.NoError(t, err)
		assert.NotNil(t, cfg.ClientCert.PrivateKey)
		assert.Nil(t, cfg.ServerCert.PrivateKey)
	})
	t.Run("error - unable to load key pair from file", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.network.config.CertFile = "test/non-existent.pem"
		cxt.network.config.CertKeyFile = "test/non-existent.pem"
		cxt.network.config.EnableTLS = true
		cfg, err := cxt.network.buildP2PConfig("")
		assert.Nil(t, cfg)
		assert.EqualError(t, err, "unable to load node TLS client certificate (certfile=test/non-existent.pem,certkeyfile=test/non-existent.pem): open test/non-existent.pem: no such file or directory")
	})
}

func Test_lastTransactionTracker(t *testing.T) {
	tracker := lastTransactionTracker{headRefs: map[hash.SHA256Hash]bool{}}

	assert.Empty(t, tracker.heads()) // initially empty

	// Root TX
	tx0, _, _ := dag.CreateTestTransaction(0)
	_ = tracker.process(tx0, nil)
	assert.Len(t, tracker.heads(), 1)
	assert.Contains(t, tracker.heads(), tx0.Ref())

	// TX 1
	tx1, _, _ := dag.CreateTestTransaction(1, tx0.Ref())
	_ = tracker.process(tx1, nil)
	assert.Len(t, tracker.heads(), 1)
	assert.Contains(t, tracker.heads(), tx1.Ref())

	// TX 2 (branch from root)
	tx2, _, _ := dag.CreateTestTransaction(2, tx0.Ref())
	_ = tracker.process(tx2, nil)
	assert.Len(t, tracker.heads(), 2)
	assert.Contains(t, tracker.heads(), tx1.Ref())
	assert.Contains(t, tracker.heads(), tx2.Ref())

	// TX 3 (merges 1 and 2)
	tx3, _, _ := dag.CreateTestTransaction(2, tx1.Ref(), tx2.Ref())
	_ = tracker.process(tx3, nil)
	assert.Len(t, tracker.heads(), 1)
	assert.Contains(t, tracker.heads(), tx3.Ref())
}

func createNetwork(ctrl *gomock.Controller) *networkTestContext {
	p2pAdapter := p2p2.NewMockAdapter(ctrl)
	protocol := proto.NewMockProtocol(ctrl)
	graph := dag.NewMockDAG(ctrl)
	payload := dag.NewMockPayloadStore(ctrl)
	publisher := dag.NewMockPublisher(ctrl)
	networkConfig := TestNetworkConfig()
	networkConfig.TrustStoreFile = "test/truststore.pem"
	networkConfig.CertFile = "test/certificate-and-key.pem"
	networkConfig.CertKeyFile = "test/certificate-and-key.pem"
	networkConfig.EnableTLS = true
	keyStore := crypto.NewMockKeyStore(ctrl)
	keyResolver := types.NewMockKeyResolver(ctrl)
	network := NewNetworkInstance(networkConfig, keyResolver)
	network.p2pNetwork = p2pAdapter
	network.protocol = protocol
	network.graph = graph
	network.payloadStore = payload
	network.publisher = publisher
	network.startTime.Store(time.Now())
	return &networkTestContext{
		network:     network,
		p2pAdapter:  p2pAdapter,
		protocol:    protocol,
		graph:       graph,
		payload:     payload,
		publisher:   publisher,
		keyStore:    keyStore,
		keyResolver: keyResolver,
	}
}

type stat struct {
}

func (s stat) Name() string {
	return "key"
}

func (s stat) String() string {
	return "value"
}
