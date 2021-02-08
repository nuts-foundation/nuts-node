/*
 * Copyright (C) 2020. Nuts community
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
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/nuts-foundation/nuts-node/network/proto"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

type networkTestContext struct {
	network    *NetworkEngine
	p2pNetwork *p2p.MockP2PNetwork
	protocol   *proto.MockProtocol
	graph      *dag.MockDAG
	payload    *dag.MockPayloadStore
	keyStore   *crypto.MockKeyStore
	publisher  *dag.MockPublisher
}

func TestNetwork_ListDocuments(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		cxt.graph.EXPECT().All().Return([]dag.Document{dag.CreateTestDocumentWithJWK(1)}, nil)
		docs, err := cxt.network.ListDocuments()
		assert.Len(t, docs, 1)
		assert.NoError(t, err)
	})
}

func TestNetwork_GetDocument(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		cxt.graph.EXPECT().Get(gomock.Any())
		cxt.network.GetDocument(hash.EmptyHash())
	})
}

func TestNetwork_GetDocumentContents(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		document := dag.CreateTestDocumentWithJWK(1)
		cxt.graph.EXPECT().Get(document.Ref()).Return(document, nil)
		cxt.payload.EXPECT().ReadPayload(document.PayloadHash())
		cxt.network.GetDocumentPayload(document.Ref())
	})
}

func TestNetwork_Subscribe(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		cxt.publisher.EXPECT().Subscribe("some-type", nil)
		cxt.network.Subscribe("some-type", nil)
	})
}

func TestNetwork_Diagnostics(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
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
		cxt := createNetwork(t, ctrl)
		cxt.protocol.EXPECT().Configure(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		cxt.p2pNetwork.EXPECT().Configure(gomock.Any())
		err := cxt.network.Configure(core.NutsConfig{Datadir: io.TestDirectory(t)})
		if !assert.NoError(t, err) {
			return
		}
	})
	t.Run("unable to create datadir", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(t, ctrl)
		err := cxt.network.Configure(core.NutsConfig{Datadir: "network_test.go"})
		assert.Error(t, err)
	})
}

func TestNetwork_CreateDocument(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t.Run("attach key", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		payload := []byte("Hello, World!")
		cxt := createNetwork(t, ctrl)
		cxt.p2pNetwork.EXPECT().Start()
		cxt.p2pNetwork.EXPECT().Configured().Return(true)
		cxt.protocol.EXPECT().Start()
		cxt.graph.EXPECT().Heads().Return(nil)
		cxt.graph.EXPECT().Add(gomock.Any())
		cxt.payload.EXPECT().WritePayload(hash.SHA256Sum(payload), payload)
		cxt.keyStore.EXPECT().GetPublicKey("signing-key", gomock.Any()).Return(privateKey.PublicKey, nil)
		cxt.keyStore.EXPECT().SignJWS(gomock.Any(), gomock.Any(), gomock.Eq("signing-key")).DoAndReturn(func(payload []byte, protectedHeaders map[string]interface{}, kid interface{}) (string, error) {
			return crypto.NewTestSigner().SignJWS(payload, protectedHeaders, "")
		})
		cxt.publisher.EXPECT().Start()
		err := cxt.network.Start()
		if !assert.NoError(t, err) {
			return
		}
		_, err = cxt.network.CreateDocument(documentType, payload, "signing-key", true, time.Now())
		assert.NoError(t, err)
	})
	t.Run("detached key", func(t *testing.T) {
		payload := []byte("Hello, World!")
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cxt := createNetwork(t, ctrl)
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
		_, err = cxt.network.CreateDocument(documentType, payload, "signing-key", false, time.Now())
		assert.NoError(t, err)
	})
}

func TestNetwork_Start(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		cxt.p2pNetwork.EXPECT().Start()
		cxt.p2pNetwork.EXPECT().Configured().Return(true)
		cxt.protocol.EXPECT().Start()
		cxt.publisher.EXPECT().Start()
		err := cxt.network.Start()
		if !assert.NoError(t, err) {
			return
		}
	})
	t.Run("ok - NetworkEngine offline", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
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
		cxt := createNetwork(t, ctrl)
		cxt.p2pNetwork.EXPECT().Stop()
		err := cxt.network.Shutdown()
		assert.NoError(t, err)
	})
	t.Run("error - stop returns error", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		cxt.p2pNetwork.EXPECT().Stop().Return(errors.New("failed"))
		err := cxt.network.Shutdown()
		assert.EqualError(t, err, "failed")
	})
}

func TestNetwork_buildP2PNetworkConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Run("ok - TLS enabled", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		cxt.network.Config.GrpcAddr = ":5555"
		cxt.network.Config.EnableTLS = true
		cxt.network.Config.CertFile = "test/certificate-and-key.pem"
		cxt.network.Config.CertKeyFile = "test/certificate-and-key.pem"
		cfg, err := cxt.network.buildP2PConfig("")
		assert.NotNil(t, cfg)
		assert.NoError(t, err)
		assert.NotNil(t, cfg.ClientCert.PrivateKey)
		assert.NotNil(t, cfg.ServerCert.PrivateKey)
	})
	t.Run("ok - TLS disabled", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		cxt.network.Config.GrpcAddr = ":5555"
		cxt.network.Config.EnableTLS = false
		cfg, err := cxt.network.buildP2PConfig("")
		assert.NotNil(t, cfg)
		assert.NoError(t, err)
		assert.NotNil(t, cfg.ClientCert.PrivateKey)
		assert.Nil(t, cfg.ServerCert.PrivateKey)
	})
	t.Run("ok - gRPC server not bound", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		cxt.network.Config.GrpcAddr = ""
		cxt.network.Config.EnableTLS = true
		cfg, err := cxt.network.buildP2PConfig("")
		assert.NotNil(t, cfg)
		assert.NoError(t, err)
		assert.NotNil(t, cfg.ClientCert.PrivateKey)
		assert.Nil(t, cfg.ServerCert.PrivateKey)
	})
	t.Run("error - unable to load key pair from file", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		cxt.network.Config.CertFile = "test/non-existent.pem"
		cxt.network.Config.CertKeyFile = "test/non-existent.pem"
		cxt.network.Config.EnableTLS = true
		cfg, err := cxt.network.buildP2PConfig("")
		assert.Nil(t, cfg)
		assert.EqualError(t, err, "unable to load node TLS client certificate (certFile=test/non-existent.pem,certKeyFile=test/non-existent.pem): open test/non-existent.pem: no such file or directory")
	})
}

func createNetwork(t *testing.T, ctrl *gomock.Controller) *networkTestContext {
	p2pNetwork := p2p.NewMockP2PNetwork(ctrl)
	protocol := proto.NewMockProtocol(ctrl)
	graph := dag.NewMockDAG(ctrl)
	payload := dag.NewMockPayloadStore(ctrl)
	publisher := dag.NewMockPublisher(ctrl)
	testDirectory := io.TestDirectory(t)
	networkConfig := TestNetworkConfig(testDirectory)
	networkConfig.TrustStoreFile = "test/truststore.pem"
	networkConfig.CertFile = "test/certificate-and-key.pem"
	networkConfig.CertKeyFile = "test/certificate-and-key.pem"
	networkConfig.PublicAddr = "foo:8080"
	keyStore := crypto.NewMockKeyStore(ctrl)
	network := NewNetworkInstance(networkConfig, keyStore)
	network.p2pNetwork = p2pNetwork
	network.protocol = protocol
	network.documentGraph = graph
	network.payloadStore = payload
	network.publisher = publisher
	return &networkTestContext{
		network:    network,
		p2pNetwork: p2pNetwork,
		protocol:   protocol,
		graph:      graph,
		payload:    payload,
		publisher:  publisher,
		keyStore:   keyStore,
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
