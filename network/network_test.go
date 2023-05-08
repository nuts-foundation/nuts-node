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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/stretchr/testify/require"

	"github.com/golang/mock/gomock"
	"github.com/nats-io/nats.go"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/test/io"
	vdrTypes "github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
)

const (
	testTruststoreFile        = "../test/pki/truststore.pem"
	testCertAndKeyFile        = "../test/pki/certificate-and-key.pem"
	testInvalidCertAndKeyFile = "../test/pki/invalid-cert.pem"
)

var nodeDID, _ = did.ParseDID("did:nuts:test")

type networkTestContext struct {
	network           *Network
	connectionManager *transport.MockConnectionManager
	state             *dag.MockState
	keyStore          crypto.KeyStore
	keyStorage        spi.Storage
	keyResolver       *vdrTypes.MockKeyResolver
	protocol          *transport.MockProtocol
	docResolver       *vdrTypes.MockDocResolver
	docFinder         *vdrTypes.MockDocFinder
	eventPublisher    *events.MockEvent
}

func (cxt *networkTestContext) start() error {
	cxt.connectionManager.EXPECT().Start()
	cxt.protocol.EXPECT().Start()
	cxt.state.EXPECT().Start()

	return cxt.network.Start()
}

func TestNetwork_ListTransactionsInRange(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Run("ok - full dag", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		cxt.state.EXPECT().FindBetweenLC(gomock.Any(), uint32(0), uint32(dag.MaxLamportClock)).Return([]dag.Transaction{dag.CreateTestTransactionWithJWK(1)}, nil)
		docs, err := cxt.network.ListTransactionsInRange(0, dag.MaxLamportClock)
		assert.Len(t, docs, 1)
		assert.NoError(t, err)
	})
	t.Run("ok - range query", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		cxt.state.EXPECT().FindBetweenLC(gomock.Any(), uint32(3), uint32(5))
		_, err := cxt.network.ListTransactionsInRange(3, 5)
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
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		cxt.state.EXPECT().GetTransaction(gomock.Any(), gomock.Any())
		cxt.network.GetTransaction(hash.EmptyHash())
	})
}

func TestNetwork_GetTransactionPayload(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Run("ok", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		transaction := dag.CreateTestTransactionWithJWK(1)
		cxt.state.EXPECT().GetTransaction(gomock.Any(), transaction.Ref()).Return(transaction, nil)
		cxt.state.EXPECT().ReadPayload(gomock.Any(), transaction.PayloadHash())
		cxt.network.GetTransactionPayload(transaction.Ref())
	})
	t.Run("ok - TX not found", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		transaction := dag.CreateTestTransactionWithJWK(1)
		cxt.state.EXPECT().GetTransaction(gomock.Any(), transaction.Ref()).Return(nil, dag.ErrTransactionNotFound)
		payload, err := cxt.network.GetTransactionPayload(transaction.Ref())
		assert.ErrorIs(t, err, dag.ErrPayloadNotFound)
		assert.Nil(t, payload)
	})
	t.Run("ok - payload not found", func(t *testing.T) {
		cxt := createNetwork(t, ctrl)
		transaction := dag.CreateTestTransactionWithJWK(1)
		cxt.state.EXPECT().GetTransaction(gomock.Any(), transaction.Ref()).Return(transaction, nil)
		cxt.state.EXPECT().ReadPayload(gomock.Any(), transaction.PayloadHash()).Return(nil, dag.ErrPayloadNotFound)
		payload, err := cxt.network.GetTransactionPayload(transaction.Ref())
		assert.ErrorIs(t, err, dag.ErrPayloadNotFound)
		assert.Nil(t, payload)
	})
}

func TestNetwork_Diagnostics(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl, func(config *Config) {
			config.NodeDID = "did:nuts:localio"
		})
		// Diagnostics from deps
		cxt.connectionManager.EXPECT().Diagnostics().Return([]core.DiagnosticResult{stat{}, stat{}})
		cxt.protocol.EXPECT().Diagnostics().Return([]core.DiagnosticResult{stat{}, stat{}})
		cxt.state.EXPECT().Diagnostics().Return([]core.DiagnosticResult{stat{}, stat{}})

		diagnostics := cxt.network.Diagnostics()

		assert.Len(t, diagnostics, 4)
		assert.Equal(t, "connections", diagnostics[0].Name())
		assert.Equal(t, fmt.Sprintf("protocol_v%d", math.MaxInt), diagnostics[1].Name())
		assert.Equal(t, "state", diagnostics[2].Name())
		nodeDIDStat := core.GenericDiagnosticResult{Title: "node_did", Outcome: did.MustParseDID("did:nuts:localio")}
		assert.Equal(t, nodeDIDStat, diagnostics[3])
	})
}

//nolint:funlen
func TestNetwork_Configure(t *testing.T) {
	t.Run("ok - configured node DID", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		test := createNetwork(t, ctrl, func(config *Config) {
			config.NodeDID = "did:nuts:test"
		})
		test.protocol.EXPECT().Configure(gomock.Any())

		err := test.network.Configure(core.TestServerConfig(core.ServerConfig{Datadir: io.TestDirectory(t)}))

		require.NoError(t, err)
		assert.Equal(t, "did:nuts:test", test.network.nodeDID.String())
	})
	t.Run("ok - auto-resolve node DID", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		ctx := createNetwork(t, ctrl)
		ctx.protocol.EXPECT().Configure(gomock.Any())

		err := ctx.network.Configure(core.TestServerConfig(core.ServerConfig{Datadir: io.TestDirectory(t)}))
		require.NoError(t, err)
	})
	t.Run("ok - no DID set in strict mode, should return empty node DID", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		test := createNetwork(t, ctrl)
		test.protocol.EXPECT().Configure(gomock.Any())

		err := test.network.Configure(core.TestServerConfig(core.ServerConfig{Datadir: io.TestDirectory(t), Strictmode: true}))
		require.NoError(t, err)
		assert.Empty(t, test.network.nodeDID)
	})

	t.Run("error - configured node DID invalid", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		ctx := createNetwork(t, ctrl)
		ctx.network.config.NodeDID = "invalid"

		err := ctx.network.Configure(core.TestServerConfig(core.ServerConfig{Datadir: io.TestDirectory(t)}))
		assert.EqualError(t, err, "configured NodeDID is invalid: invalid DID: input does not begin with 'did:' prefix")
	})

	t.Run("ok - TLS enabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ctx := createNetwork(t, ctrl)
		ctx.protocol.EXPECT().Configure(gomock.Any())
		ctx.network.connectionManager = nil

		cfg := *core.NewServerConfig()
		cfg.Datadir = io.TestDirectory(t)
		*cfg.LegacyTLS = core.NetworkTLSConfig{
			Enabled:        true,
			TrustStoreFile: testTruststoreFile,
			CertFile:       testCertAndKeyFile,
			CertKeyFile:    testCertAndKeyFile,
		}
		err := ctx.network.Configure(cfg)

		require.NoError(t, err)
	})

	t.Run("ok - TLS disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ctx := createNetwork(t, ctrl)
		ctx.protocol.EXPECT().Configure(gomock.Any())
		ctx.network.connectionManager = nil

		err := ctx.network.Configure(core.TestServerConfig(core.ServerConfig{Datadir: io.TestDirectory(t)}))

		require.NoError(t, err)
	})

	t.Run("error - TLS disabled in strict mode", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ctx := createNetwork(t, ctrl)
		ctx.protocol.EXPECT().Configure(gomock.Any())
		ctx.network.connectionManager = nil

		err := ctx.network.Configure(core.TestServerConfig(core.ServerConfig{Datadir: io.TestDirectory(t), Strictmode: true}))

		assert.EqualError(t, err, "disabling TLS in strict mode is not allowed")
	})

	t.Run("ok - gRPC server not bound (but outbound connections are still supported)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ctx := createNetwork(t, ctrl, func(config *Config) {
			config.GrpcAddr = ""
		})
		ctx.protocol.EXPECT().Configure(gomock.Any())

		err := ctx.network.Configure(core.TestServerConfig(core.ServerConfig{Datadir: io.TestDirectory(t)}))

		require.NoError(t, err)
	})

	t.Run("error - unable to configure protocol", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		ctx := createNetwork(t, ctrl)
		ctx.protocol.EXPECT().Configure(gomock.Any()).Return(errors.New("failed"))

		err := ctx.network.Configure(core.TestServerConfig(core.ServerConfig{Datadir: io.TestDirectory(t)}))
		assert.EqualError(t, err, "error while configuring protocol *transport.MockProtocol: failed")
	})
	t.Run("unable to create datadir", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		prov := storage.NewMockProvider(ctrl)
		ctx := createNetwork(t, ctrl)
		ctx.network.storeProvider = prov
		ctx.network.connectionManager = nil
		prov.EXPECT().GetKVStore(gomock.Any(), gomock.Any()).Return(nil, errors.New("failed"))

		err := ctx.network.Configure(core.TestServerConfig(core.ServerConfig{Datadir: "network_test.go"}))
		assert.Error(t, err)
	})
	t.Run("ok - protocol not enabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		ctx := createNetwork(t, ctrl, func(config *Config) {
			config.Protocols = []int{2} // do not enable TestProtocol with version math.MaxInt
		})

		err := ctx.network.Configure(core.TestServerConfig(core.ServerConfig{Datadir: io.TestDirectory(t)}))

		assert.NoError(t, err)
		assert.Empty(t, ctx.network.protocols)
	})

	t.Run("error - unable to open connections store", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		ctx := createNetwork(t, ctrl)
		ctx.protocol.EXPECT().Configure(gomock.Any()).AnyTimes()
		prov := storage.NewMockProvider(ctrl)
		ctx.network.storeProvider = prov
		ctx.network.connectionManager = nil
		prov.EXPECT().GetKVStore(gomock.Any(), gomock.Any())
		prov.EXPECT().GetKVStore(gomock.Any(), gomock.Any()).Return(nil, errors.New("failed"))

		err := ctx.network.Configure(core.TestServerConfig(core.ServerConfig{Datadir: io.TestDirectory(t)}))

		assert.EqualError(t, err, "failed to open connections store: failed")
	})
}

func TestNetwork_PeerDiagnostics(t *testing.T) {
	ctrl := gomock.NewController(t)

	// Protocol 1: peer A (with diagnostics), B (without diagnostics)
	// Protocol 2: peer B (with diagnostics)
	// Result should be peer A and B without diagnostics

	cxt := createNetwork(t, ctrl)
	cxt.protocol.EXPECT().PeerDiagnostics().Return(map[transport.PeerID]transport.Diagnostics{
		"A": {
			SoftwareID: "A",
			Uptime:     time.Second,
			Peers:      []transport.PeerID{"A"},
		},
		"B": {},
	})
	protocol2 := transport.NewMockProtocol(ctrl)
	protocol2.EXPECT().Start()
	protocol2.EXPECT().PeerDiagnostics().Return(map[transport.PeerID]transport.Diagnostics{
		"B": {
			SoftwareID: "B",
			Uptime:     time.Second,
			Peers:      []transport.PeerID{"A"},
		},
	})
	cxt.network.protocols = append(cxt.network.protocols, protocol2)

	err := cxt.start()
	require.NoError(t, err)

	actual := cxt.network.PeerDiagnostics()

	assert.Equal(t, "A", actual["A"].SoftwareID)
	assert.Equal(t, "B", actual["B"].SoftwareID)
}

func TestNetwork_CreateTransaction(t *testing.T) {
	key := crypto.NewTestKey("signing-key")
	ctx := audit.TestContext()
	t.Run("ok - attach key", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		payload := []byte("Hello, World!")
		cxt := createNetwork(t, ctrl)
		err := cxt.start()
		require.NoError(t, err)

		cxt.state.EXPECT().Head(gomock.Any())
		cxt.state.EXPECT().Add(gomock.Any(), gomock.Any(), payload)

		_, err = cxt.network.CreateTransaction(ctx, TransactionTemplate(payloadType, payload, key).WithAttachKey())
		assert.NoError(t, err)
	})
	t.Run("ok - detached key", func(t *testing.T) {
		payload := []byte("Hello, World!")
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		err := cxt.start()
		require.NoError(t, err)
		cxt.state.EXPECT().Head(gomock.Any())
		cxt.state.EXPECT().Add(gomock.Any(), gomock.Any(), payload)
		tx, err := cxt.network.CreateTransaction(ctx, TransactionTemplate(payloadType, payload, key))
		assert.NoError(t, err)
		assert.Len(t, tx.Previous(), 0)
	})
	t.Run("ok - additional prevs", func(t *testing.T) {
		payload := []byte("Hello, World!")
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)

		// Register root TX on head tracker
		rootTX, _, _ := dag.CreateTestTransaction(0)

		// 'Register' prev on DAG
		additionalPrev, _, _ := dag.CreateTestTransaction(1)
		cxt.state.EXPECT().GetTransaction(gomock.Any(), rootTX.Ref()).Return(rootTX, nil)
		cxt.state.EXPECT().GetTransaction(gomock.Any(), additionalPrev.Ref()).Return(additionalPrev, nil).Times(2)
		cxt.state.EXPECT().IsPayloadPresent(gomock.Any(), additionalPrev.PayloadHash()).Return(true, nil)
		cxt.state.EXPECT().Head(gomock.Any()).Return(rootTX.Ref(), nil)

		cxt.state.EXPECT().Add(gomock.Any(), gomock.Any(), payload)

		err := cxt.start()
		require.NoError(t, err)

		tx, err := cxt.network.CreateTransaction(ctx, TransactionTemplate(payloadType, payload, key).WithAdditionalPrevs([]hash.SHA256Hash{additionalPrev.Ref()}))

		require.NoError(t, err)
		assert.Len(t, tx.Previous(), 2)
		assert.Equal(t, rootTX.Ref(), tx.Previous()[0])
		assert.Equal(t, additionalPrev.Ref(), tx.Previous()[1])
	})
	t.Run("error - additional prev is missing payload", func(t *testing.T) {
		payload := []byte("Hello, World!")
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		err := cxt.start()
		require.NoError(t, err)

		// 'Register' prev on DAG
		prev, _, _ := dag.CreateTestTransaction(1)
		cxt.state.EXPECT().GetTransaction(gomock.Any(), prev.Ref()).Return(prev, nil)
		cxt.state.EXPECT().IsPayloadPresent(gomock.Any(), prev.PayloadHash()).Return(false, nil)

		tx, err := cxt.network.CreateTransaction(ctx, TransactionTemplate(payloadType, payload, key).WithAdditionalPrevs([]hash.SHA256Hash{prev.Ref()}))

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "additional prev is unknown or missing payload")
		assert.Nil(t, tx)
	})
	t.Run("private transaction", func(t *testing.T) {
		key := crypto.NewTestKey("signing-key")
		sender, _ := did.ParseDID("did:nuts:sender")
		senderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		receiver, _ := did.ParseDID("did:nuts:receiver")
		receiverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			payload := []byte("Hello, World!")
			cxt := createNetwork(t, ctrl)
			err := cxt.start()
			require.NoError(t, err)

			cxt.network.nodeDID = nodeDID

			cxt.state.EXPECT().Head(gomock.Any())
			cxt.state.EXPECT().Add(gomock.Any(), gomock.Any(), payload)

			cxt.keyResolver.EXPECT().ResolveKeyAgreementKey(*sender).Return(senderKey.Public(), nil)
			cxt.keyResolver.EXPECT().ResolveKeyAgreementKey(*receiver).Return(receiverKey.Public(), nil)

			_, err = cxt.network.CreateTransaction(ctx, TransactionTemplate(payloadType, payload, key).WithPrivate([]did.DID{*sender, *receiver}))
			assert.NoError(t, err)
		})
		t.Run("node DID not configured", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			payload := []byte("Hello, World!")
			cxt := createNetwork(t, ctrl)
			err := cxt.start()
			require.NoError(t, err)

			_, err = cxt.network.CreateTransaction(ctx, TransactionTemplate(payloadType, payload, key).WithPrivate([]did.DID{*sender, *receiver}))
			assert.EqualError(t, err, "node DID must be configured to create private transactions")
		})
	})
	t.Run("error - failed to calculate LC", func(t *testing.T) {
		payload := []byte("Hello, World!")
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		// Register root TX on head tracker
		rootTX, _, _ := dag.CreateTestTransaction(0)
		// 'Register' prev on DAG
		additionalPrev, _, _ := dag.CreateTestTransaction(1)
		cxt.state.EXPECT().GetTransaction(gomock.Any(), rootTX.Ref()).Return(nil, errors.New("custom"))
		cxt.state.EXPECT().GetTransaction(gomock.Any(), additionalPrev.Ref()).Return(additionalPrev, nil)
		cxt.state.EXPECT().IsPayloadPresent(gomock.Any(), additionalPrev.PayloadHash()).Return(true, nil)
		cxt.state.EXPECT().Head(gomock.Any()).Return(rootTX.Ref(), nil)

		_, err := cxt.network.CreateTransaction(ctx, TransactionTemplate(payloadType, payload, key).WithAdditionalPrevs([]hash.SHA256Hash{additionalPrev.Ref()}))

		assert.EqualError(t, err, "unable to calculate clock value for new transaction: custom")
	})
}

func TestNetwork_Start(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)

		err := cxt.start()

		require.NoError(t, err)
		assert.NotNil(t, cxt.network.startTime.Load())
	})
	t.Run("ok - connects to bootstrap nodes", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl, func(config *Config) {
			config.BootstrapNodes = []string{"bootstrap-node-1", "", "bootstrap-node-2"}
		})
		cxt.docFinder.EXPECT().Find(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return([]did.Document{}, nil)
		cxt.connectionManager.EXPECT().Connect("bootstrap-node-1", did.DID{}, gomock.Any())
		cxt.connectionManager.EXPECT().Connect("bootstrap-node-2", did.DID{}, gomock.Any())

		err := cxt.start()

		require.NoError(t, err)
	})
	t.Run("error - cannot verify node DID's key material", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		cxt.network.strictMode = true
		cxt.network.nodeDID = nodeDID
		cxt.state.EXPECT().Start()

		cxt.docResolver.EXPECT().Resolve(*nodeDID, nil).Return(nil, nil, did.DeactivatedErr) //
		err := cxt.network.Start()

		assert.EqualError(t, err, "DID document can't be resolved (did=did:nuts:test): supplied DID is deactivated")
	})
	t.Run("error - state start failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		cxt.state.EXPECT().Start().Return(errors.New("failed"))

		err := cxt.network.Start()

		assert.EqualError(t, err, "failed")
	})
	t.Run("error - protocol start failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		cxt.state.EXPECT().Start()
		cxt.protocol.EXPECT().Start().Return(errors.New("proto failed"))

		err := cxt.network.Start()

		assert.EqualError(t, err, "proto failed")
	})
	t.Run("error - connection manager start failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		cxt.state.EXPECT().Start()
		cxt.protocol.EXPECT().Start()
		cxt.connectionManager.EXPECT().Start().Return(errors.New("cm failed"))

		err := cxt.network.Start()

		assert.EqualError(t, err, "cm failed")
	})
}

func TestNetwork_validateNodeDID(t *testing.T) {
	ctx := context.Background()
	keyID := *nodeDID
	keyID.Fragment = "some-key"
	key := crypto.NewTestKey(keyID.String()).(*crypto.TestKey).PrivateKey
	documentWithoutNutsCommService := &did.Document{
		KeyAgreement: []did.VerificationRelationship{
			{VerificationMethod: &did.VerificationMethod{ID: keyID}},
		},
	}
	completeDocument := &did.Document{
		KeyAgreement: []did.VerificationRelationship{
			{VerificationMethod: &did.VerificationMethod{ID: keyID}},
		},
		Service: []did.Service{
			{
				Type:            transport.NutsCommServiceType,
				ServiceEndpoint: "grpc://nuts.nl:5555",
			},
		},
	}
	certificate, err := tls.LoadX509KeyPair(testCertAndKeyFile, testCertAndKeyFile)
	require.NoError(t, err)
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	require.NoError(t, err)
	t.Run("ok - configured node DID successfully resolves", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		_ = cxt.keyStorage.SavePrivateKey(ctx, keyID.String(), certificate.PrivateKey)
		cxt.network.certificate = certificate
		cxt.network.nodeDID = nodeDID
		cxt.docResolver.EXPECT().Resolve(*nodeDID, nil).MinTimes(1).Return(completeDocument, &vdrTypes.DocumentMetadata{}, nil)
		err := cxt.network.validateNodeDID(ctx, *nodeDID)
		assert.NoError(t, err)
	})
	t.Run("error - configured node DID does not resolve to a DID document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		cxt.network.nodeDID = nodeDID
		cxt.docResolver.EXPECT().Resolve(*nodeDID, nil).Return(nil, nil, did.DeactivatedErr)

		err = cxt.network.validateNodeDID(ctx, *nodeDID)

		assert.ErrorIs(t, err, did.DeactivatedErr)
	})
	t.Run("error - configured node DID does not have key agreement key", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		cxt.network.strictMode = true
		cxt.network.nodeDID = nodeDID
		cxt.docResolver.EXPECT().Resolve(*nodeDID, nil).Return(&did.Document{}, &vdrTypes.DocumentMetadata{}, nil)

		err := cxt.network.validateNodeDID(ctx, *nodeDID)

		assert.EqualError(t, err, "DID document does not contain a keyAgreement key, register a keyAgreement key (did=did:nuts:test)")
	})
	t.Run("error - configured node DID has key agreement key, but is not present in key store", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		cxt.network.strictMode = true
		cxt.network.nodeDID = nodeDID
		cxt.docResolver.EXPECT().Resolve(*nodeDID, nil).Return(completeDocument, &vdrTypes.DocumentMetadata{}, nil)

		err := cxt.network.validateNodeDID(ctx, *nodeDID)

		assert.EqualError(t, err, "keyAgreement private key is not present in key store, recover your key material or register a new keyAgreement key (did=did:nuts:test,kid=did:nuts:test#some-key)")
	})
	t.Run("error - configured node DID does not have NutsComm service", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		_ = cxt.keyStorage.SavePrivateKey(ctx, keyID.String(), key)
		cxt.network.strictMode = true
		cxt.network.nodeDID = nodeDID
		cxt.docResolver.EXPECT().Resolve(*nodeDID, nil).MinTimes(1).Return(documentWithoutNutsCommService, &vdrTypes.DocumentMetadata{}, nil)

		err := cxt.network.validateNodeDID(ctx, *nodeDID)

		assert.EqualError(t, err, "unable to resolve NutsComm service endpoint, register it on the DID document (did=did:nuts:test): service not found in DID Document")
	})
	t.Run("error - cannot marshal NutsComm service", func(t *testing.T) {
		old := completeDocument.Service[0].ServiceEndpoint
		completeDocument.Service[0].ServiceEndpoint = struct{}{}
		defer func() { completeDocument.Service[0].ServiceEndpoint = old }()

		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		_ = cxt.keyStorage.SavePrivateKey(ctx, keyID.String(), key)
		cxt.network.strictMode = true
		cxt.network.certificate = certificate
		cxt.network.nodeDID = nodeDID
		cxt.docResolver.EXPECT().Resolve(*nodeDID, nil).MinTimes(1).Return(completeDocument, &vdrTypes.DocumentMetadata{}, nil)

		err := cxt.network.validateNodeDID(ctx, *nodeDID)

		assert.EqualError(t, err, "invalid NutsComm service endpoint: endpoint not a string")
	})
	t.Run("error - cannot parse NutsComm service", func(t *testing.T) {
		old := completeDocument.Service[0].ServiceEndpoint
		completeDocument.Service[0].ServiceEndpoint = string([]byte{0})
		defer func() { completeDocument.Service[0].ServiceEndpoint = old }()

		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		_ = cxt.keyStorage.SavePrivateKey(ctx, keyID.String(), key)
		cxt.network.strictMode = true
		cxt.network.certificate = certificate
		cxt.network.nodeDID = nodeDID
		cxt.docResolver.EXPECT().Resolve(*nodeDID, nil).MinTimes(1).Return(completeDocument, &vdrTypes.DocumentMetadata{}, nil)

		err := cxt.network.validateNodeDID(ctx, *nodeDID)

		assert.EqualError(t, err, "invalid NutsComm service endpoint: parse \"\\x00\": net/url: invalid control character in URL")
	})
	t.Run("error - no TLS certificate", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		_ = cxt.keyStorage.SavePrivateKey(ctx, keyID.String(), key)
		cxt.network.strictMode = true
		cxt.network.nodeDID = nodeDID
		cxt.docResolver.EXPECT().Resolve(*nodeDID, nil).MinTimes(1).Return(completeDocument, &vdrTypes.DocumentMetadata{}, nil)

		err := cxt.network.validateNodeDID(ctx, *nodeDID)

		assert.EqualError(t, err, "missing TLS certificate")
	})
	t.Run("error - wrong TLS certificate", func(t *testing.T) {
		old := completeDocument.Service[0].ServiceEndpoint
		completeDocument.Service[0].ServiceEndpoint = "grpc://not.nuts.nl:5555"
		defer func() { completeDocument.Service[0].ServiceEndpoint = old }()

		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		_ = cxt.keyStorage.SavePrivateKey(ctx, keyID.String(), key)
		cxt.network.strictMode = true
		cxt.network.certificate = certificate
		cxt.network.nodeDID = nodeDID
		cxt.docResolver.EXPECT().Resolve(*nodeDID, nil).MinTimes(1).Return(completeDocument, &vdrTypes.DocumentMetadata{}, nil)

		err := cxt.network.validateNodeDID(ctx, *nodeDID)

		assert.EqualError(t, err, "none of the DNS names in TLS certificate match the NutsComm service endpoint (nodeDID=did:nuts:test, NutsComm=grpc://not.nuts.nl:5555)")
	})
}

func TestNetwork_Shutdown(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ctx := createNetwork(t, ctrl)
		ctx.protocol.EXPECT().Configure(gomock.Any())
		ctx.protocol.EXPECT().Stop()
		ctx.connectionManager.EXPECT().Stop()

		err := ctx.network.Configure(core.TestServerConfig(core.ServerConfig{Datadir: io.TestDirectory(t)}))

		require.NoError(t, err)
		err = ctx.network.Shutdown()
		assert.NoError(t, err)
	})

	t.Run("multiple calls", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		cxt.state.EXPECT().Shutdown().MinTimes(1)
		cxt.protocol.EXPECT().Stop().MinTimes(1)
		cxt.connectionManager.EXPECT().Stop().MinTimes(1)
		err := cxt.network.Shutdown()
		assert.NoError(t, err)
		err = cxt.network.Shutdown()
		assert.NoError(t, err)
		err = cxt.network.Shutdown()
		assert.NoError(t, err)
	})
}

func TestNetwork_Reprocess(t *testing.T) {
	foundMutex := sync.Mutex{}
	tx, _, _ := dag.CreateTestTransaction(0)

	newSetup := func(t *testing.T) (*networkTestContext, events.Event) {
		ctrl := gomock.NewController(t)
		ctx := createNetwork(t, ctrl)
		eventManager := events.NewTestManager(t)
		ctx.network.eventPublisher = eventManager
		return ctx, eventManager
	}

	subscribe := func(ctx context.Context, t *testing.T, eventManager events.Event, wg *sync.WaitGroup, counter *int) {
		conn, _, err := eventManager.Pool().Acquire(ctx)
		require.NoError(t, err)

		err = events.NewDisposableStream("REPROCESS_test", []string{"REPROCESS.*"}, 10).Subscribe(conn, t.Name(), "REPROCESS.*", func(m *nats.Msg) {
			foundMutex.Lock()
			defer foundMutex.Unlock()
			*counter++
			wg.Done()
			err := m.Ack()
			assert.NoError(t, err)
		})
		require.NoError(t, err)
	}

	t.Run("hits", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		setup, eventManager := newSetup(t)
		setup.state.EXPECT().FindBetweenLC(gomock.Any(), uint32(0), uint32(1000)).Return([]dag.Transaction{tx}, nil)
		setup.state.EXPECT().ReadPayload(gomock.Any(), tx.PayloadHash()).Return([]byte("payload"), nil)
		var counter int
		wg := sync.WaitGroup{}
		wg.Add(1)

		subscribe(ctx, t, eventManager, &wg, &counter)

		_, err := setup.network.Reprocess(ctx, "application/did+json")
		require.NoError(t, err)
		wg.Wait()
		assert.Equal(t, 1, counter)
	})

	t.Run("mismatch", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		setup, eventManager := newSetup(t)
		setup.state.EXPECT().FindBetweenLC(gomock.Any(), uint32(0), uint32(1000)).Return([]dag.Transaction{tx}, nil)
		var counter int
		wg := sync.WaitGroup{}

		subscribe(ctx, t, eventManager, &wg, &counter)

		_, err := setup.network.Reprocess(ctx, "application/did+vc")
		require.NoError(t, err)
		wg.Wait()
		assert.Equal(t, 0, counter)
	})

	t.Run("error", func(t *testing.T) {
		t.Run("query", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			testErr := errors.New("test error")

			setup, eventManager := newSetup(t)
			setup.state.EXPECT().FindBetweenLC(gomock.Any(), uint32(0), uint32(1000)).Return(nil, testErr)
			var counter int
			wg := sync.WaitGroup{}

			subscribe(ctx, t, eventManager, &wg, &counter)

			_, err := setup.network.Reprocess(ctx, "application/did+vc")
			wg.Wait()
			assert.ErrorIs(t, err, testErr)
			assert.Equal(t, 0, counter)
		})

		t.Run("payload", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			testErr := errors.New("test error")

			setup, eventManager := newSetup(t)
			setup.state.EXPECT().FindBetweenLC(gomock.Any(), uint32(0), uint32(1000)).Return([]dag.Transaction{tx}, nil)
			setup.state.EXPECT().ReadPayload(gomock.Any(), tx.PayloadHash()).Return(nil, testErr)
			var counter int
			wg := sync.WaitGroup{}

			subscribe(ctx, t, eventManager, &wg, &counter)

			_, err := setup.network.Reprocess(ctx, "application/did+json")
			wg.Wait()
			assert.ErrorIs(t, err, testErr)
			assert.Equal(t, 0, counter)
		})
	})
}

func TestNetwork_Subscribers(t *testing.T) {
	ctrl := gomock.NewController(t)
	cxt := createNetwork(t, ctrl)
	notifier := dag.NewNotifier("test", func(event dag.Event) (bool, error) {
		return true, nil
	})
	cxt.state.EXPECT().Notifiers().Return([]dag.Notifier{notifier})

	subscribers := cxt.network.Subscribers()

	assert.Len(t, subscribers, 1)
}

func TestNetwork_CleanupSubscriberEvents(t *testing.T) {
	ctrl := gomock.NewController(t)
	cxt := createNetwork(t, ctrl)
	kvStore, _ := storage.NewTestStorageEngine(t.TempDir()).GetProvider("test").GetKVStore("test", storage.PersistentStorageClass)
	notifier := dag.NewNotifier("test", func(event dag.Event) (bool, error) {
		return true, nil
	}, dag.WithPersistency(kvStore))
	cxt.state.EXPECT().Notifiers().Return([]dag.Notifier{notifier})
	err := kvStore.Write(context.Background(), func(tx stoabs.WriteTx) error {
		_ = notifier.Save(tx, dag.Event{
			Type:    "test",
			Hash:    hash.RandomHash(),
			Retries: 99,
			Error:   "no prefix match",
		})
		return notifier.Save(tx, dag.Event{
			Type:    "test",
			Hash:    hash.RandomHash(),
			Retries: 99,
			Error:   "prefix match",
		})
	})
	require.NoError(t, err)

	err = cxt.network.CleanupSubscriberEvents("test", "prefix")
	require.NoError(t, err)
	failedEvents, err := notifier.GetFailedEvents()
	require.NoError(t, err)

	require.Len(t, failedEvents, 1)
	assert.Equal(t, "no prefix match", failedEvents[0].Error)
}

func TestNetwork_collectDiagnostics(t *testing.T) {
	const txNum = 5
	const expectedVersion = "development (0)"
	const expectedID = "https://github.com/nuts-foundation/nuts-node"
	expectedPeer := transport.Peer{ID: "abc", Address: "123"}

	ctrl := gomock.NewController(t)
	cxt := createNetwork(t, ctrl)
	cxt.state.EXPECT().Diagnostics().Return([]core.DiagnosticResult{core.GenericDiagnosticResult{Title: dag.TransactionCountDiagnostic, Outcome: uint(txNum)}})

	cxt.connectionManager.EXPECT().Peers().Return([]transport.Peer{expectedPeer})

	actual := cxt.network.collectDiagnosticsForPeers()

	assert.Equal(t, expectedID, actual.SoftwareID)
	assert.Equal(t, expectedVersion, actual.SoftwareVersion)
	assert.Equal(t, []transport.PeerID{expectedPeer.ID}, actual.Peers)
	assert.Equal(t, uint32(txNum), actual.NumberOfTransactions)
	assert.NotEmpty(t, actual.Uptime)
}

func TestNetwork_ServiceDiscovery(t *testing.T) {
	peerDID, _ := did.ParseDID("did:nuts:peer")
	peerAddress := "peer.com:5555"
	peerDocument := did.Document{
		ID: *peerDID,
		Service: []did.Service{
			{
				Type:            transport.NutsCommServiceType,
				ServiceEndpoint: "grpc://" + peerAddress,
			},
		},
	}
	delayFn := func(delay time.Duration) *time.Duration { return &delay }
	t.Run("ok - no service discovery", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ctx := createNetwork(t, ctrl)
		ctx.network.DiscoverServices(*peerDID)
	})
	t.Run("ok - new node", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ctx := createNetwork(t, ctrl, func(config *Config) {
			config.EnableDiscovery = true
		})
		ctx.docResolver.EXPECT().Resolve(*peerDID, nil).Return(&peerDocument, nil, nil)
		ctx.connectionManager.EXPECT().Connect(peerAddress, *peerDID, delayFn(newNodeConnectionDelay))
		ctx.network.assumeNewNode = true

		ctx.network.DiscoverServices(*peerDID)
	})
	t.Run("ok - existing node", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ctx := createNetwork(t, ctrl, func(config *Config) {
			config.EnableDiscovery = true
		})
		ctx.docResolver.EXPECT().Resolve(*peerDID, nil).Return(&peerDocument, nil, nil)
		ctx.connectionManager.EXPECT().Connect(peerAddress, *peerDID, delayFn(time.Duration(0)))

		ctx.network.DiscoverServices(*peerDID)
	})
	t.Run("nok - DID document resolve failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ctx := createNetwork(t, ctrl, func(config *Config) {
			config.EnableDiscovery = true
		})
		ctx.docResolver.EXPECT().Resolve(*peerDID, nil).Return(nil, nil, errors.New("failed"))

		ctx.network.DiscoverServices(*peerDID)

		// asserts network.connectionManager.Connect is not called
	})
}

func Test_connectToKnownNodes(t *testing.T) {
	t.Run("endpoint unmarshalling", func(t *testing.T) {
		doc := did.Document{ID: *nodeDID}

		serviceEndpoints := []struct {
			name     string
			endpoint interface{}
		}{
			{
				name:     "incorrect serviceEndpoint data type",
				endpoint: []interface{}{},
			},
			{
				name:     "incorrect serviceEndpoint URL",
				endpoint: "::",
			},
			{
				name:     "incorrect serviceEndpoint URL scheme",
				endpoint: "https://endpoint",
			},
		}

		for _, sp := range serviceEndpoints {
			t.Run(sp.name, func(t *testing.T) {
				ctrl := gomock.NewController(t)

				// Use actual test instance because the unit test's createNetwork mocks too much for us
				network := NewTestNetworkInstance(t)
				docFinder := vdrTypes.NewMockDocFinder(ctrl)
				network.didDocumentFinder = docFinder
				network.config.EnableDiscovery = true

				doc2 := doc
				doc2.Service = []did.Service{
					{
						Type:            transport.NutsCommServiceType,
						ServiceEndpoint: sp.endpoint,
					},
				}
				docFinder.EXPECT().Find(gomock.Any(), gomock.Any(), gomock.Any()).Return([]did.Document{doc2}, nil)

				_ = network.connectToKnownNodes(did.DID{}) // no local node DID

				// assert
				// cxt.connectionManager.Connect is not called
			})
		}
	})
	t.Run("local node should not be discovered", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		// Use actual test instance because the unit test's createNetwork mocks too much for us
		network := NewTestNetworkInstance(t)
		docFinder := vdrTypes.NewMockDocFinder(ctrl)
		network.didDocumentFinder = docFinder
		network.config.EnableDiscovery = true
		connectionManager := transport.NewMockConnectionManager(ctrl)
		network.connectionManager = connectionManager

		localDocument := did.Document{
			ID: *nodeDID,
			Service: []did.Service{
				{
					Type:            transport.NutsCommServiceType,
					ServiceEndpoint: "grpc://local.com:5555", // reserved and IP addresses (local) are not auto-discovered
				},
			},
		}
		peerDID, _ := did.ParseDID("did:nuts:peer")
		peerAddress := "peer.com:5555"
		peerDocument := did.Document{
			ID: *peerDID,
			Service: []did.Service{
				{
					Type:            transport.NutsCommServiceType,
					ServiceEndpoint: "grpc://" + peerAddress,
				},
			},
		}
		docFinder.EXPECT().Find(gomock.Any()).Return([]did.Document{peerDocument, localDocument}, nil)
		// Only expect Connect() call for peer
		connectionManager.EXPECT().Connect(peerAddress, *peerDID, nil)

		_ = network.connectToKnownNodes(*nodeDID)
	})
	t.Run("bootstrap always connect without delay", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		ctx := createNetwork(t, ctrl, func(config *Config) {
			config.EnableDiscovery = true
			config.BootstrapNodes = []string{"bootstrap"}
		})
		// ctx.docFinder.EXPECT().Find().Return(nothing, nil) // called from createNetwork

		// expect Connect() call with delay == 0 for bootstrap node
		ctx.connectionManager.EXPECT().Connect("bootstrap", did.DID{}, nil)

		_ = ctx.network.connectToKnownNodes(*nodeDID)
	})
}

func TestNetwork_calculateLamportClock(t *testing.T) {
	root := dag.CreateTestTransactionWithJWK(1)

	t.Run("returns 0 for root", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)

		clock, err := cxt.network.calculateLamportClock(context.Background(), nil)

		require.NoError(t, err)
		assert.Equal(t, uint32(0), clock)
	})

	t.Run("returns 1 for next TX", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		cxt.state.EXPECT().GetTransaction(gomock.Any(), root.Ref()).Return(root, nil)

		clock, err := cxt.network.calculateLamportClock(context.Background(), []hash.SHA256Hash{root.Ref()})

		require.NoError(t, err)
		assert.Equal(t, uint32(1), clock)
	})

	t.Run("returns correct number for complex situation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		A := dag.CreateTestTransactionWithJWK(2, root)
		B := dag.CreateTestTransactionWithJWK(3, root, A)
		C := dag.CreateTestTransactionWithJWK(4, B, root)
		cxt.state.EXPECT().GetTransaction(gomock.Any(), root.Ref()).Return(root, nil)
		cxt.state.EXPECT().GetTransaction(gomock.Any(), C.Ref()).Return(C, nil)

		clock, err := cxt.network.calculateLamportClock(context.Background(), []hash.SHA256Hash{C.Ref(), root.Ref()})

		require.NoError(t, err)
		assert.Equal(t, uint32(4), clock)
	})

	t.Run("error - failed to fetch TX", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cxt := createNetwork(t, ctrl)
		cxt.state.EXPECT().GetTransaction(gomock.Any(), root.Ref()).Return(nil, errors.New("custom"))

		clock, err := cxt.network.calculateLamportClock(context.Background(), []hash.SHA256Hash{root.Ref()})

		assert.Error(t, err)
		assert.Equal(t, uint32(0), clock)
	})
}

func TestNetwork_checkHealth(t *testing.T) {
	trustStore, err := core.LoadTrustStore(testTruststoreFile)
	require.NoError(t, err)
	certificate, err := tls.LoadX509KeyPair(testCertAndKeyFile, testCertAndKeyFile)
	require.NoError(t, err)
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	require.NoError(t, err)
	t.Run("TLS", func(t *testing.T) {
		t.Run("up", func(t *testing.T) {
			n := Network{
				trustStore:  trustStore,
				certificate: certificate,
				nodeDID:     &did.DID{},
			}

			result := n.CheckHealth()

			assert.Equal(t, core.HealthStatusUp, result[healthTLS].Status)
		})
		t.Run("expired", func(t *testing.T) {
			trustStore, err := core.LoadTrustStore(testTruststoreFile)
			require.NoError(t, err)
			certificate, err := tls.LoadX509KeyPair(testInvalidCertAndKeyFile, testInvalidCertAndKeyFile)
			require.NoError(t, err)
			certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
			require.NoError(t, err)
			n := Network{
				trustStore:  trustStore,
				certificate: certificate,
				nodeDID:     &did.DID{},
			}

			result := n.CheckHealth()

			assert.Equal(t, core.HealthStatusDown, result[healthTLS].Status)
			assert.Equal(t, "x509: certificate signed by unknown authority", result[healthTLS].Details)
		})
	})

	t.Run("authentication", func(t *testing.T) {
		keyID := *nodeDID
		keyID.Fragment = "some-key"
		completeDocument := &did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: keyID}},
			},
			Service: []did.Service{
				{
					Type:            transport.NutsCommServiceType,
					ServiceEndpoint: "grpc://nuts.nl:5555",
				},
			},
		}
		t.Run("up - correctly configured node DID", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			cxt := createNetwork(t, ctrl)
			_ = cxt.keyStorage.SavePrivateKey(context.Background(), keyID.String(), certificate.PrivateKey)
			cxt.network.trustStore = trustStore
			cxt.network.certificate = certificate
			cxt.network.nodeDID = nodeDID
			cxt.docResolver.EXPECT().Resolve(*nodeDID, nil).MinTimes(1).Return(completeDocument, &vdrTypes.DocumentMetadata{}, nil)

			health := cxt.network.CheckHealth()

			assert.Equal(t, core.HealthStatusUp, health[healthAuthConfig].Status)
			assert.Nil(t, health["auth"].Details)
		})
		t.Run("up - no node DID", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			cxt := createNetwork(t, ctrl)

			health := cxt.network.CheckHealth()

			assert.Equal(t, core.HealthStatusUp, health[healthAuthConfig].Status)
			assert.Equal(t, "no node DID", health[healthAuthConfig].Details)

		})
		t.Run("down - authentication failed", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			cxt := createNetwork(t, ctrl)
			cxt.network.nodeDID = nodeDID
			cxt.docResolver.EXPECT().Resolve(*nodeDID, nil).Return(nil, nil, did.DeactivatedErr)

			health := cxt.network.CheckHealth()

			assert.Equal(t, core.HealthStatusDown, health[healthAuthConfig].Status)
			assert.Equal(t, "DID document can't be resolved (did=did:nuts:test): supplied DID is deactivated", health[healthAuthConfig].Details)
		})
	})

}

func createNetwork(t *testing.T, ctrl *gomock.Controller, cfgFn ...func(config *Config)) *networkTestContext {
	state := dag.NewMockState(ctrl)
	prot := transport.NewMockProtocol(ctrl)
	prot.EXPECT().Version().AnyTimes().Return(math.MaxInt)
	connectionManager := transport.NewMockConnectionManager(ctrl)
	networkConfig := TestNetworkConfig()

	for _, fn := range cfgFn {
		fn(&networkConfig)
	}
	keyStorage := crypto.NewMemoryStorage()
	keyStore := crypto.NewTestCryptoInstance(keyStorage)
	keyResolver := vdrTypes.NewMockKeyResolver(ctrl)
	docResolver := vdrTypes.NewMockDocResolver(ctrl)
	docFinder := vdrTypes.NewMockDocFinder(ctrl)
	eventPublisher := events.NewMockEvent(ctrl)
	storageEngine := storage.NewTestStorageEngine(io.TestDirectory(t))
	t.Cleanup(func() {
		_ = storageEngine.Shutdown()
	})
	// required when starting the network, it searches for nodes to connect to
	docFinder.EXPECT().Find(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return([]did.Document{}, nil)
	network := NewNetworkInstance(networkConfig, keyResolver, keyStore, docResolver, docFinder, eventPublisher, storageEngine.GetProvider(ModuleName))
	network.state = state
	network.connectionManager = connectionManager
	network.protocols = []transport.Protocol{prot}
	network.didDocumentResolver = docResolver
	if len(networkConfig.NodeDID) > 0 {
		nodeDID := did.MustParseDID(networkConfig.NodeDID)
		network.nodeDID = &nodeDID
	}
	startTime := time.Now()
	network.startTime.Store(&startTime)
	return &networkTestContext{
		network:           network,
		connectionManager: connectionManager,
		protocol:          prot,
		state:             state,
		keyStore:          keyStore,
		keyStorage:        keyStorage,
		keyResolver:       keyResolver,
		docResolver:       docResolver,
		docFinder:         docFinder,
		eventPublisher:    eventPublisher,
	}
}

type stat struct {
}

func (s stat) Result() interface{} {
	return "value"
}

func (s stat) Name() string {
	return "key"
}

func (s stat) String() string {
	return "value"
}
