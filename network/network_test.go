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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/nuts-foundation/nuts-node/network/proto"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
)

type networkTestContext struct {
	network     *Network
	p2pNetwork  *p2p.MockP2PNetwork
	protocol    *proto.MockProtocol
	graph       *dag.MockDAG
	payload     *dag.MockPayloadStore
	keyStore    *crypto.MockAccessor
	publisher   *dag.MockPublisher
	keyResolver *types.MockKeyResolver
}

func TestNetwork_ListTransactions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(ctrl)
		cxt.graph.EXPECT().All().Return([]dag.Transaction{dag.CreateTestTransactionWithJWK(1)}, nil)
		docs, err := cxt.network.ListTransactions()
		assert.Len(t, docs, 1)
		assert.NoError(t, err)
	})
}

func TestNetwork_Name(t *testing.T) {
	assert.Equal(t, "Network", (&Network{}).Name())
}

func TestNetwork_ConfigKey(t *testing.T) {
	assert.Equal(t, "network", (&Network{}).ConfigKey())
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
		cxt.graph.EXPECT().Get(gomock.Any())
		cxt.network.GetTransaction(hash.EmptyHash())
	})
}

func TestNetwork_GetTransactionContents(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(ctrl)
		transaction := dag.CreateTestTransactionWithJWK(1)
		cxt.graph.EXPECT().Get(transaction.Ref()).Return(transaction, nil)
		cxt.payload.EXPECT().ReadPayload(transaction.PayloadHash())
		cxt.network.GetTransactionPayload(transaction.Ref())
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
		cxt.p2pNetwork.EXPECT().Diagnostics().Return([]core.DiagnosticResult{stat{}, stat{}})
		diagnostics := cxt.network.Diagnostics()
		assert.Len(t, diagnostics, 4)
	})
}

func TestNetwork_Configure(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.protocol.EXPECT().Configure(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		cxt.p2pNetwork.EXPECT().Configure(gomock.Any())
		err := cxt.network.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
		if !assert.NoError(t, err) {
			return
		}
	})
	t.Run("certs not configured (offline mode)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.protocol.EXPECT().Configure(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
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
		cxt.protocol.EXPECT().Configure(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
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
		cxt.protocol.EXPECT().Configure(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		cxt.p2pNetwork.EXPECT().Configure(gomock.Any())
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
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t.Run("ok - attach key", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		payload := []byte("Hello, World!")
		cxt := createNetwork(ctrl)
		cxt.p2pNetwork.EXPECT().Start()
		cxt.p2pNetwork.EXPECT().Configured().Return(true)
		cxt.protocol.EXPECT().Start()
		cxt.graph.EXPECT().Heads().Return(nil)
		cxt.graph.EXPECT().Add(gomock.Any())
		cxt.payload.EXPECT().WritePayload(hash.SHA256Sum(payload), payload)
		cxt.keyStore.EXPECT().SignJWS(gomock.Any(), gomock.Any(), gomock.Eq("signing-key")).DoAndReturn(func(payload []byte, protectedHeaders map[string]interface{}, kid interface{}) (string, error) {
			return crypto.NewTestSigner().SignJWS(payload, protectedHeaders, "")
		})
		cxt.publisher.EXPECT().Start()
		err := cxt.network.Start()
		if !assert.NoError(t, err) {
			return
		}
		_, err = cxt.network.CreateTransaction(payloadType, payload, "signing-key", privateKey.PublicKey, cxt.keyStore, time.Now(), []hash.SHA256Hash{})
		assert.NoError(t, err)
	})
	t.Run("ok - detached key", func(t *testing.T) {
		payload := []byte("Hello, World!")
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.p2pNetwork.EXPECT().Start()
		cxt.p2pNetwork.EXPECT().Configured().Return(true)
		cxt.protocol.EXPECT().Start()
		cxt.graph.EXPECT().Heads().Return(nil)
		cxt.graph.EXPECT().Add(gomock.Any())
		cxt.payload.EXPECT().WritePayload(hash.SHA256Sum(payload), payload)
		cxt.keyStore.EXPECT().SignJWS(gomock.Any(), gomock.Any(), gomock.Eq("signing-key")).DoAndReturn(func(payload []byte, protectedHeaders map[string]interface{}, kid interface{}) (string, error) {
			return crypto.NewTestSigner().SignJWS(payload, protectedHeaders, "")
		})
		cxt.publisher.EXPECT().Start()
		err := cxt.network.Start()
		if !assert.NoError(t, err) {
			return
		}
		tx, err := cxt.network.CreateTransaction(payloadType, payload, "signing-key", nil, cxt.keyStore, time.Now(), []hash.SHA256Hash{})
		assert.NoError(t, err)
		assert.Len(t, tx.Previous(), 0)
	})
	t.Run("ok - additional prevs", func(t *testing.T) {
		prev, _ := hash.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
		payload := []byte("Hello, World!")
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(ctrl)
		cxt.p2pNetwork.EXPECT().Start()
		cxt.p2pNetwork.EXPECT().Configured().Return(true)
		cxt.protocol.EXPECT().Start()
		cxt.graph.EXPECT().Heads().Return(nil)
		cxt.graph.EXPECT().Add(gomock.Any())
		cxt.payload.EXPECT().WritePayload(hash.SHA256Sum(payload), payload)
		cxt.keyStore.EXPECT().SignJWS(gomock.Any(), gomock.Any(), gomock.Eq("signing-key")).DoAndReturn(func(payload []byte, protectedHeaders map[string]interface{}, kid interface{}) (string, error) {
			return crypto.NewTestSigner().SignJWS(payload, protectedHeaders, "")
		})
		cxt.publisher.EXPECT().Start()
		err := cxt.network.Start()
		if !assert.NoError(t, err) {
			return
		}
		tx, err := cxt.network.CreateTransaction(payloadType, payload, "signing-key", nil, cxt.keyStore, time.Now(), []hash.SHA256Hash{prev})

		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, tx.Previous(), 1)
		assert.Equal(t, prev, tx.Previous()[0])
	})
}

func TestNetwork_Start(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(ctrl)
		cxt.p2pNetwork.EXPECT().Start()
		cxt.p2pNetwork.EXPECT().Configured().Return(true)
		cxt.protocol.EXPECT().Start()
		cxt.publisher.EXPECT().Start()
		err := cxt.network.Start()
		if !assert.NoError(t, err) {
			return
		}
	})
	t.Run("ok - offline", func(t *testing.T) {
		cxt := createNetwork(ctrl)
		cxt.p2pNetwork.EXPECT().Configured().Return(false)
		cxt.protocol.EXPECT().Start()
		cxt.publisher.EXPECT().Start()
		err := cxt.network.Start()
		if !assert.NoError(t, err) {
			return
		}
	})
}

func TestNetwork_Shutdown(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(ctrl)
		cxt.p2pNetwork.EXPECT().Stop()
		err := cxt.network.Shutdown()
		assert.NoError(t, err)
	})
	t.Run("error - stop returns error", func(t *testing.T) {
		cxt := createNetwork(ctrl)
		cxt.p2pNetwork.EXPECT().Stop().Return(errors.New("failed"))
		err := cxt.network.Shutdown()
		assert.EqualError(t, err, "failed")
	})
}

func TestNetwork_buildP2PNetworkConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok - TLS enabled", func(t *testing.T) {
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
		cxt := createNetwork(ctrl)
		cxt.network.config.CertFile = "test/non-existent.pem"
		cxt.network.config.CertKeyFile = "test/non-existent.pem"
		cxt.network.config.EnableTLS = true
		cfg, err := cxt.network.buildP2PConfig("")
		assert.Nil(t, cfg)
		assert.EqualError(t, err, "unable to load node TLS client certificate (certfile=test/non-existent.pem,certkeyfile=test/non-existent.pem): open test/non-existent.pem: no such file or directory")
	})
}

func createNetwork(ctrl *gomock.Controller) *networkTestContext {
	p2pNetwork := p2p.NewMockP2PNetwork(ctrl)
	protocol := proto.NewMockProtocol(ctrl)
	graph := dag.NewMockDAG(ctrl)
	payload := dag.NewMockPayloadStore(ctrl)
	publisher := dag.NewMockPublisher(ctrl)
	networkConfig := TestNetworkConfig()
	networkConfig.TrustStoreFile = "test/truststore.pem"
	networkConfig.CertFile = "test/certificate-and-key.pem"
	networkConfig.CertKeyFile = "test/certificate-and-key.pem"
	networkConfig.EnableTLS = true
	keyStore := crypto.NewMockAccessor(ctrl)
	keyResolver := types.NewMockKeyResolver(ctrl)
	network := NewNetworkInstance(networkConfig, keyResolver)
	network.p2pNetwork = p2pNetwork
	network.protocol = protocol
	network.graph = graph
	network.payloadStore = payload
	network.publisher = publisher
	return &networkTestContext{
		network:     network,
		p2pNetwork:  p2pNetwork,
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
