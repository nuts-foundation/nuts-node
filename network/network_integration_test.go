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
	"crypto"
	"fmt"
	"hash/crc32"
	"path"
	"sync"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"github.com/nuts-foundation/nuts-node/network/transport/v1"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/store"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/test/io"
)

const defaultTimeout = 5 * time.Second
const payloadType = "test/transaction"

var mutex = sync.Mutex{}
var receivedTransactions = make(map[string][]dag.Transaction, 0)
var vdrStore vdr.Store
var keyStore nutsCrypto.KeyStore

func TestNetworkIntegration_HappyFlow(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	resetIntegrationTest()
	key := nutsCrypto.NewTestKey("key")
	expectedDocLogSize := 0

	// Start 3 nodes: bootstrap, node1 and node2. Node 1 and 2 connect to the bootstrap node and should discover
	// each other that way.
	bootstrap := startNode(t, "integration_bootstrap", testDirectory)
	node1 := startNode(t, "integration_node1", testDirectory)
	node1.connectionManager.Connect(nameToAddress(t, "integration_bootstrap"))
	node2 := startNode(t, "integration_node2", testDirectory)
	node2.connectionManager.Connect(nameToAddress(t, "integration_bootstrap"))

	// Wait until nodes are connected
	if !test.WaitFor(t, func() (bool, error) {
		return len(bootstrap.connectionManager.Peers()) == 2, nil
	}, defaultTimeout, "time-out while waiting for node 1 and 2 to be connected") {
		return
	}

	// Publish first transaction on node1, we expect in to come out on node2 and bootstrap
	if !addTransactionAndWaitForItToArrive(t, "doc1", key, node1, "integration_node2", "integration_bootstrap") {
		return
	}
	expectedDocLogSize++

	// Now the graph has a root, and node2 can publish a transaction
	if !addTransactionAndWaitForItToArrive(t, "doc2", key, node2, "integration_node1", "integration_bootstrap") {
		return
	}
	expectedDocLogSize++

	// Now assert that all nodes have received all transactions
	waitForTransactions := func(node string, graph dag.DAG) bool {
		return test.WaitFor(t, func() (bool, error) {
			var (
				docs []dag.Transaction
				err  error
			)
			if docs, err = graph.FindBetween(context.Background(), dag.MinTime(), dag.MaxTime()); err != nil {
				return false, err
			}
			return len(docs) == expectedDocLogSize, nil
		}, defaultTimeout, "%s: time-out while waiting for %d transactions", node, expectedDocLogSize)
	}
	waitForTransactions("bootstrap", bootstrap.graph)
	waitForTransactions("node 1", node1.graph)
	waitForTransactions("node 2", node2.graph)

	// Can we request the diagnostics?
	fmt.Printf("%v\n", bootstrap.Diagnostics())
	fmt.Printf("%v\n", node1.Diagnostics())
	fmt.Printf("%v\n", node2.Diagnostics())
}

func TestNetworkIntegration_NodesConnectToEachOther(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	resetIntegrationTest()

	// Start 2 nodes: node1 and node2, where each connects to the other
	node1 := startNode(t, "node1", testDirectory)
	node2 := startNode(t, "node2", testDirectory)

	// Now connect node1 to node2 and wait for them to set up
	node1.connectionManager.Connect(nameToAddress(t, "node2"))
	if !test.WaitFor(t, func() (bool, error) {
		return len(node1.connectionManager.Peers()) == 1 && len(node2.connectionManager.Peers()) == 1, nil
	}, defaultTimeout, "time-out while waiting for node 1 and 2 to be connected") {
		return
	}

	// Now instruct node2 to connect to node1
	node2.connectionManager.Connect(nameToAddress(t, "node1"))
	time.Sleep(time.Second)
	assert.Len(t, node1.connectionManager.Peers(), 1)
	assert.Len(t, node2.connectionManager.Peers(), 1)
}

func TestNetworkIntegration_NodeDIDAuthentication(t *testing.T) {
	t.Run("mutual auth", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest()

		// Start 2 nodes: node1 and node2, where node1 specifies a node DID that node2 can't authenticate
		node1 := startNode(t, "node1", testDirectory, func(cfg *Config) {
			cfg.NodeDID = "did:nuts:node1"
		})
		node2 := startNode(t, "node2", testDirectory, func(cfg *Config) {
			cfg.NodeDID = "did:nuts:node2"
		})
		// Now connect node1 to node2 and wait for them to set up
		node1.connectionManager.Connect(nameToAddress(t, "node2"))

		test.WaitFor(t, func() (bool, error) {
			return len(node1.connectionManager.Peers()) == 1 && len(node2.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for node1 to connect to node2")
	})
	t.Run("node DID auth sent client (authenticated by server) fails", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest()

		// Start 2 nodes: node1 and node2, where node1 specifies a node DID that node2 can't authenticate
		node1 := startNode(t, "node1", testDirectory, func(cfg *Config) {
			cfg.NodeDID = "did:nuts:node1"
		})
		node2 := startNode(t, "node2", testDirectory)

		// Set node DID to an unauthenticatable DID, such that authentication must fail
		malloryDID, _ := did.ParseDID("did:nuts:mallory")
		node1.nodeDIDResolver.(*transport.FixedNodeDIDResolver).NodeDID = *malloryDID

		// Now connect node1 to node2 and wait for them to set up
		node1.connectionManager.Connect(nameToAddress(t, "node2"))
		if !test.WaitFor(t, func() (bool, error) {
			diagnostics := node1.connectionManager.Diagnostics()
			connectorsStats := diagnostics[3].(grpc.ConnectorsStats)
			// Assert we tried to connect at least once
			return connectorsStats[0].ConnectAttempts >= 1, nil
		}, defaultTimeout, "time-out while waiting for node 1 to try to connect") {
			return
		}

		// Assert there are no peers, because authentication failed
		assert.Empty(t, node1.connectionManager.Peers())
		assert.Empty(t, node2.connectionManager.Peers())
	})
	t.Run("node DID auth sent by server (authenticated by client) fails", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest()

		// Start 2 nodes: node1 and node2, where node2 specifies a node DID that node1 can't authenticate
		node1 := startNode(t, "node1", testDirectory)
		node2 := startNode(t, "node2", testDirectory, func(cfg *Config) {
			cfg.NodeDID = "did:nuts:node2"
		})

		// Set node DID to an unauthenticatable DID, such that authentication must fail
		malloryDID, _ := did.ParseDID("did:nuts:mallory")
		node2.nodeDIDResolver.(*transport.FixedNodeDIDResolver).NodeDID = *malloryDID

		// Now connect node1 to node2 and wait for them to set up
		node1.connectionManager.Connect(nameToAddress(t, "node2"))
		if !test.WaitFor(t, func() (bool, error) {
			diagnostics := node1.connectionManager.Diagnostics()
			connectorsStats := diagnostics[3].(grpc.ConnectorsStats)
			// Assert we tried to connect at least once
			return connectorsStats[0].ConnectAttempts >= 1, nil
		}, defaultTimeout, "time-out while waiting for node 1 to try to connect") {
			return
		}

		// Assert there are no peers, because authentication failed
		assert.Empty(t, node1.connectionManager.Peers())
		assert.Empty(t, node2.connectionManager.Peers())
	})
}

func TestNetworkIntegration_PrivateTransaction(t *testing.T) {
	t.Run("happy flow", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest()
		key := nutsCrypto.NewTestKey("key")

		// Start 2 nodes: node1 and node2, node1 sends a private TX to node 2
		node1 := startNode(t, "node1", testDirectory, func(cfg *Config) {
			cfg.NodeDID = "did:nuts:node1"
		})
		node2 := startNode(t, "node2", testDirectory, func(cfg *Config) {
			cfg.NodeDID = "did:nuts:node2"
		})
		// Now connect node1 to node2 and wait for them to set up
		node1.connectionManager.Connect(nameToAddress(t, "node2"))

		test.WaitFor(t, func() (bool, error) {
			return len(node1.connectionManager.Peers()) == 1 && len(node2.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for node1 to connect to node2")

		node1DID, _ := node1.nodeDIDResolver.Resolve()
		node2DID, _ := node2.nodeDIDResolver.Resolve()
		tpl := TransactionTemplate(payloadType, []byte("private TX"), key).
			WithAttachKey().
			WithPrivate([]did.DID{node1DID, node2DID})
		tx, err := node1.CreateTransaction(tpl)
		if !assert.NoError(t, err) {
			return
		}
		waitForTransaction(t, tx, "node2")
	})
}

func TestNetworkIntegration_OutboundConnectionReconnects(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	resetIntegrationTest()

	// Given node1 and node2
	// Given node1 connects to node2
	// When node2 shuts down
	// Then node1 isn't connected to node2
	// When node2 starts again
	// Then node1 should reconnect to node2
	node1 := startNode(t, "node1", testDirectory)
	node2 := startNode(t, "node2", testDirectory)

	// Now connect node1 to node2 and wait for them to set up
	node1.connectionManager.Connect(nameToAddress(t, "node2"))
	if !test.WaitFor(t, func() (bool, error) {
		return len(node1.connectionManager.Peers()) == 1 && len(node2.connectionManager.Peers()) == 1, nil
	}, defaultTimeout, "time-out while waiting for node 1 and 2 to be connected") {
		return
	}

	// Now shut down node2 and for wait node1 to notice it
	_ = node2.Shutdown()
	if !test.WaitFor(t, func() (bool, error) {
		return len(node1.connectionManager.Peers()) == 0, nil
	}, defaultTimeout, "time-out while waiting for node 1 to notice shut down node") {
		return
	}

	// Now start node2 again, node1 should reconnect
	node2 = startNode(t, "node2", testDirectory) // important to start a new instance, otherwise PeerID isn't regenerated
	if !test.WaitFor(t, func() (bool, error) {
		return len(node1.connectionManager.Peers()) == 1, nil
	}, defaultTimeout, "time-out while waiting for node 1 to reconnect to node 2") {
		return
	}
}

func resetIntegrationTest() {
	// in an integration test we want everything to work as intended, disable test speedup and re-enable file sync for bbolt
	defaultBBoltOptions.NoSync = false

	receivedTransactions = make(map[string][]dag.Transaction, 0)
	vdrStore = store.NewMemoryStore()
	keyStore = nutsCrypto.NewTestCryptoInstance()

	// Write DID Document for node1
	writeDIDDocument := func(subject string) {
		nodeDID, _ := did.ParseDID(subject)
		document := did.Document{ID: *nodeDID}
		kid := *nodeDID
		kid.Fragment = "key-1"
		key, _ := keyStore.New(func(_ crypto.PublicKey) (string, error) {
			return kid.String(), nil
		})
		verificationMethod, _ := did.NewVerificationMethod(kid, ssi.JsonWebKey2020, *nodeDID, key.Public())
		document.VerificationMethod.Add(verificationMethod)
		document.KeyAgreement.Add(verificationMethod)
		document.Service = []did.Service{{
			Type:            transport.NutsCommServiceType,
			ServiceEndpoint: "grpc://localhost:5555", // Must match TLS SAN DNSName
		}}
		err := vdrStore.Write(document, vdr.DocumentMetadata{})
		if err != nil {
			panic(err)
		}
	}
	writeDIDDocument("did:nuts:node1")
	writeDIDDocument("did:nuts:node2")
}

func addTransactionAndWaitForItToArrive(t *testing.T, payload string, key nutsCrypto.Key, sender *Network, receivers ...string) bool {
	expectedTransaction, err := sender.CreateTransaction(TransactionTemplate(payloadType, []byte(payload), key).WithAttachKey())
	if !assert.NoError(t, err) {
		return false
	}
	return waitForTransaction(t, expectedTransaction, receivers...)
}

func waitForTransaction(t *testing.T, tx dag.Transaction, receivers ...string) bool {
	for _, receiver := range receivers {
		if !test.WaitFor(t, func() (bool, error) {
			mutex.Lock()
			defer mutex.Unlock()
			for _, receivedDoc := range receivedTransactions[receiver] {
				if tx.Ref().Equals(receivedDoc.Ref()) {
					return true, nil
				}
			}
			return false, nil
		}, 5*time.Second, "time-out while waiting for transaction to arrive at %s", receiver) {
			return false
		}
	}
	return true
}

func startNode(t *testing.T, name string, testDirectory string, opts ...func(cfg *Config)) *Network {
	log.Logger().Infof("Starting node: %s", name)
	logrus.SetLevel(logrus.DebugLevel)
	core.NewServerConfig().Load(&cobra.Command{})
	// Create Network instance
	config := Config{
		GrpcAddr:       fmt.Sprintf("localhost:%d", nameToPort(t, name)),
		CertFile:       "test/certificate-and-key.pem",
		CertKeyFile:    "test/certificate-and-key.pem",
		TrustStoreFile: "test/truststore.pem",
		EnableTLS:      true,
		ProtocolV1: v1.Config{
			AdvertHashesInterval:      500,
			AdvertDiagnosticsInterval: 5000,
		},
	}
	for _, f := range opts {
		f(&config)
	}

	instance := &Network{
		config:                 config,
		lastTransactionTracker: lastTransactionTracker{headRefs: make(map[hash.SHA256Hash]bool), processedTransactions: map[hash.SHA256Hash]bool{}},
		didDocumentResolver:    doc.Resolver{Store: vdrStore},
		privateKeyResolver:     keyStore,
		decrypter:              keyStore,
		keyResolver:            doc.KeyResolver{Store: vdrStore},
		nodeDIDResolver:        &transport.FixedNodeDIDResolver{},
	}
	if err := instance.Configure(core.ServerConfig{Datadir: path.Join(testDirectory, name)}); err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	instance.Subscribe(dag.TransactionPayloadAddedEvent, payloadType, func(transaction dag.Transaction, payload []byte) error {
		mutex.Lock()
		defer mutex.Unlock()
		log.Logger().Infof("transaction %s arrived at %s", string(payload), name)
		receivedTransactions[name] = append(receivedTransactions[name], transaction)
		return nil
	})
	t.Cleanup(func() {
		_ = instance.Shutdown()
	})
	return instance
}

func nameToPort(t *testing.T, name string) int {
	return int(crc32.ChecksumIEEE([]byte(t.Name()+"/"+name))%9000 + 1000)
}

func nameToAddress(t *testing.T, name string) string {
	return fmt.Sprintf("localhost:%d", nameToPort(t, name))
}
