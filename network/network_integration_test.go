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
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"hash/crc32"
	"math/rand"
	"net/url"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	v2 "github.com/nuts-foundation/nuts-node/network/transport/v2"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	grpcLib "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const defaultTimeout = 5 * time.Second
const payloadType = "test/transaction"

var mutex = sync.Mutex{}
var receivedTransactions = make(map[string][]dag.Transaction, 0)
var didStore didstore.Store
var keyStore nutsCrypto.KeyStore

func TestNetworkIntegration_HappyFlow(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	resetIntegrationTest(t)
	key := nutsCrypto.NewTestKey("key")
	expectedDocLogSize := 0

	// Start 3 nodes: bootstrap, node1 and node2. Node 1 and 2 connect to the bootstrap node and should discover
	// each other that way.
	bootstrap := startNode(t, "integration_bootstrap", testDirectory)
	node1 := startNode(t, "integration_node1", testDirectory)
	node1.network.connectionManager.Connect(nameToAddress(t, "integration_bootstrap"), did.DID{}, nil)
	node2 := startNode(t, "integration_node2", testDirectory)
	node2.network.connectionManager.Connect(nameToAddress(t, "integration_bootstrap"), did.DID{}, nil)

	// Wait until nodes are connected
	if !test.WaitFor(t, func() (bool, error) {
		return len(bootstrap.network.connectionManager.Peers()) == 2, nil
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
	waitForTransactions := func(node string, state dag.State) bool {
		return test.WaitFor(t, func() (bool, error) {
			var (
				docs []dag.Transaction
				err  error
			)
			if docs, err = state.FindBetweenLC(context.Background(), 0, dag.MaxLamportClock); err != nil {
				return false, err
			}
			return len(docs) == expectedDocLogSize, nil
		}, defaultTimeout, "%s: time-out while waiting for %d transactions", node, expectedDocLogSize)
	}
	waitForTransactions("bootstrap", bootstrap.network.state)
	waitForTransactions("node 1", node1.network.state)
	waitForTransactions("node 2", node2.network.state)

	// Can we request the diagnostics?
	fmt.Printf("%v\n", bootstrap.network.Diagnostics())
	fmt.Printf("%v\n", node1.network.Diagnostics())
	fmt.Printf("%v\n", node2.network.Diagnostics())
}

func TestNetworkIntegration_Messages(t *testing.T) {
	resetIntegrationTest(t)

	testNodes := func(t *testing.T, opts ...func(_ *core.ServerConfig, cfg *Config)) (node, node) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)

		allOpts := append([]func(*core.ServerConfig, *Config){func(_ *core.ServerConfig, cfg *Config) {
			cfg.Protocols = []int{2}
		}}, opts...)
		bootstrap := startNode(t, "integration_bootstrap", testDirectory, allOpts...)
		node1 := startNode(t, "integration_node1", testDirectory, allOpts...)

		return bootstrap, node1
	}

	waitForTransactions := func(node string, state dag.State, expectedDocLogSize int) bool {
		return test.WaitFor(t, func() (bool, error) {
			var (
				docs []dag.Transaction
				err  error
			)
			if docs, err = state.FindBetweenLC(context.Background(), 0, dag.MaxLamportClock); err != nil {
				return false, err
			}
			return len(docs) == expectedDocLogSize, nil
		}, defaultTimeout, "%s: time-out while waiting for %d transactions", node, expectedDocLogSize)
	}

	t.Run("Gossip", func(t *testing.T) {
		key := nutsCrypto.NewTestKey("key")
		expectedDocLogSize := 0

		bootstrap, node1 := testNodes(t)
		node1.network.connectionManager.Connect(nameToAddress(t, "integration_bootstrap"), did.DID{}, nil)

		// Wait until nodes are connected
		if !test.WaitFor(t, func() (bool, error) {
			return len(bootstrap.network.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for node 1 and 2 to be connected") {
			return
		}

		// create some transactions on the bootstrap node
		for i := 0; i < 10; i++ {
			if !addTransactionAndWaitForItToArrive(t, fmt.Sprintf("doc%d", i), key, bootstrap) {
				return
			}
			expectedDocLogSize++
		}

		// Now assert that all nodes have received all transactions
		waitForTransactions("node 1", node1.network.state, expectedDocLogSize)
	})

	t.Run("Gossip - sync missing transactions from slow peer", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)

		// start nodes with v1 disabled, and disable Gossip for bootstrap node
		bootstrap := startNode(t, "integration_bootstrap", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.Protocols = []int{2}
			cfg.ProtocolV2 = v2.Config{GossipInterval: 100000} // disable Gossip to simulate node1 always being behind
		})
		node1 := startNode(t, "integration_node1", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.Protocols = []int{2}
			cfg.ProtocolV2 = v2.Config{GossipInterval: 100}
		})

		// set root
		key := nutsCrypto.NewTestKey("key")
		rootTx, err := bootstrap.network.CreateTransaction(audit.TestContext(), TransactionTemplate(payloadType, []byte("root_tx"), key).WithAttachKey())
		require.NoError(t, err)
		require.NoError(t, node1.network.state.Add(context.Background(), rootTx, []byte("root_tx")))
		expectedDocLogSize := 1

		// create some transactions on the bootstrap node to get it ahead of node 1
		for i := 0; i < 10; i++ {
			if !addTransactionAndWaitForItToArrive(t, fmt.Sprintf("bootstrap_doc%d", i), key, bootstrap) {
				return
			}
			expectedDocLogSize++
		}
		// create a single transaction on node1
		if !addTransactionAndWaitForItToArrive(t, "node1_doc", nutsCrypto.NewTestKey("key_node1"), node1) {
			return
		}
		expectedDocLogSize++

		// Wait until nodes are connected
		node1.network.connectionManager.Connect(nameToAddress(t, "integration_bootstrap"), did.DID{}, nil)
		if !test.WaitFor(t, func() (bool, error) {
			return len(bootstrap.network.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for nodes to be connected") {
			return
		}

		// Now assert that the nodes have received the right
		waitForTransactions("bootstrap", bootstrap.network.state, expectedDocLogSize) // has everything
		waitForTransactions("node 1", node1.network.state, 2)                         // received no updates
	})

	t.Run("IBLT", func(t *testing.T) {
		key := nutsCrypto.NewTestKey("key")
		expectedDocLogSize := 0

		bootstrap, node1 := testNodes(t)

		// create some transactions on the bootstrap node
		for i := 0; i < 10; i++ {
			if !addTransactionAndWaitForItToArrive(t, fmt.Sprintf("doc%d", i), key, bootstrap) {
				return
			}
			expectedDocLogSize++
		}

		// now connect and wait until nodes are connected
		node1.network.connectionManager.Connect(nameToAddress(t, "integration_bootstrap"), did.DID{}, nil)
		if !test.WaitFor(t, func() (bool, error) {
			return len(bootstrap.network.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for node 1 and 2 to be connected") {
			return
		}

		// Now assert that all nodes have received all transactions
		waitForTransactions("node 1", node1.network.state, expectedDocLogSize)
	})

	t.Run("Parallel node sync", func(t *testing.T) {
		key := nutsCrypto.NewTestKey("key")
		expectedDocLogSize := 0

		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)

		node1 := startNode(t, "integration_node1", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.Protocols = []int{2}
			cfg.ProtocolV2.GossipInterval = 500
		})
		node2 := startNode(t, "integration_node2", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.Protocols = []int{2}
			cfg.ProtocolV2.GossipInterval = 500
		})
		node3 := startNode(t, "integration_node3", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.Protocols = []int{2}
			cfg.ProtocolV2.GossipInterval = 500
		})
		node1.network.connectionManager.Connect(nameToAddress(t, "integration_node2"), did.DID{}, nil)

		// Wait until nodes are connected
		if !test.WaitFor(t, func() (bool, error) {
			return len(node1.network.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for node 1 and 2 to be connected") {
			return
		}

		// create some transactions on node1
		for i := 0; i < 10; i++ {
			if !addTransactionAndWaitForItToArrive(t, fmt.Sprintf("doc%d", i), key, node1) {
				return
			}
			expectedDocLogSize++
		}

		waitForTransactions("node 2", node2.network.state, expectedDocLogSize)

		// connect node 3 to 1 and 2. It'll receive parallel updates from both nodes
		node3.network.connectionManager.Connect(nameToAddress(t, "integration_node1"), did.DID{}, nil)
		node3.network.connectionManager.Connect(nameToAddress(t, "integration_node2"), did.DID{}, nil)
		waitForTransactions("node 3", node3.network.state, expectedDocLogSize)

		xor1, _ := node1.network.state.XOR(dag.MaxLamportClock)
		xor2, _ := node2.network.state.XOR(dag.MaxLamportClock)
		xor3, _ := node3.network.state.XOR(dag.MaxLamportClock)
		assert.True(t, xor1.Equals(xor3))
		assert.True(t, xor2.Equals(xor3))
	})

	t.Run("Peer Diagnostics", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)
		bootstrap := startNode(t, "integration_bootstrap", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.Protocols = []int{2}
			cfg.ProtocolV2.DiagnosticsInterval = 50
			cfg.NodeDID = "did:nuts:node2" // certificate only contains node1, node2, and node3

		})
		node1 := startNode(t, "integration_node1", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.Protocols = []int{2}
			cfg.ProtocolV2.DiagnosticsInterval = 50
			cfg.NodeDID = "did:nuts:node1"

		})
		node1.network.connectionManager.Connect(nameToAddress(t, "integration_bootstrap"), did.MustParseDID("did:nuts:node2"), nil)

		// Wait until nodes are connected
		if !test.WaitFor(t, func() (bool, error) {
			return len(bootstrap.network.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for node 1 and 2 to be connected") {
			return
		}

		addTransactionAndWaitForItToArrive(t, "foobar", nutsCrypto.NewTestKey("key"), bootstrap, "integration_node1")

		time.Sleep(100 * time.Millisecond) // wait for diagnostics to be sent

		// Assert peer diagnostics sent from bootstrap node to node 1
		assert.Equal(t, 1, len(node1.network.PeerDiagnostics()))
		bootstrapDiag := node1.network.PeerDiagnostics()[bootstrap.network.peerID]
		assert.Equal(t, uint32(1), bootstrapDiag.NumberOfTransactions)
		assert.Equal(t, "https://github.com/nuts-foundation/nuts-node", bootstrapDiag.SoftwareID)
		assert.Equal(t, "development (0)", bootstrapDiag.SoftwareVersion)
		assert.Equal(t, []transport.PeerID{node1.network.peerID}, bootstrapDiag.Peers)

		// Assert peer diagnostics sent from bootstrap node1 to bootstrap node
		assert.Equal(t, 1, len(bootstrap.network.PeerDiagnostics()))
		node1Diag := bootstrap.network.PeerDiagnostics()[node1.network.peerID]
		assert.Equal(t, uint32(1), node1Diag.NumberOfTransactions)
		assert.Equal(t, "https://github.com/nuts-foundation/nuts-node", node1Diag.SoftwareID)
		assert.Equal(t, "development (0)", node1Diag.SoftwareVersion)
		assert.Equal(t, []transport.PeerID{bootstrap.network.peerID}, node1Diag.Peers)
	})
}

func TestNetworkIntegration_NodesConnectToEachOther(t *testing.T) {
	t.Run("authenticated connections", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)

		// Start 2 nodes: node1 and node2, where each connects to the other
		node1 := startNode(t, "node1", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node1"
		})
		node2 := startNode(t, "node2", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node2"
		})

		// Now connect node1 to node2 and wait for them to set up
		node1.network.connectionManager.Connect(nameToAddress(t, "node2"), did.MustParseDID("did:nuts:node2"), nil)
		if !test.WaitFor(t, func() (bool, error) {
			return len(node1.network.connectionManager.Peers()) == 1 && len(node2.network.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for node 1 and 2 to be connected") {
			return
		}

		// Now instruct node2 to connect to node1
		node2.network.connectionManager.Connect(nameToAddress(t, "node1"), did.MustParseDID("did:nuts:node1"), nil)
		time.Sleep(time.Second)
		// Assert that the connectors of node1 and node2 are deduplicated: since node1 already connected to node2,
		// node2 should not connect to node1 (deduplicated on nodeDID)
		assert.Len(t, node1.network.connectionManager.Peers(), 1)
		assert.Len(t, node2.network.connectionManager.Peers(), 1)
	})
	t.Run("bootstrap connections", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)

		// Start 2 nodes: node1 and node2, where each connects to the other
		node1 := startNode(t, "node1", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node1"
		})
		node2 := startNode(t, "node2", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node2"
		})

		// Now connect node1 add node2 as bootstrap connection and wait for them to set up
		node1.network.connectionManager.Connect(nameToAddress(t, "node2"), did.DID{}, nil)
		if !test.WaitFor(t, func() (bool, error) {
			return len(node1.network.connectionManager.Peers()) == 1 && len(node2.network.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for node 1 to connect to node 2") {
			return
		}

		// Now instruct node2 to connect to node1. non-bootstrap, so should be accepted
		node2.network.connectionManager.Connect(nameToAddress(t, "node1"), did.MustParseDID("did:nuts:node1"), nil)
		if !test.WaitFor(t, func() (bool, error) {
			return len(node1.network.connectionManager.Peers()) == 2 && len(node2.network.connectionManager.Peers()) == 2, nil
		}, defaultTimeout, "time-out while waiting for node 2 to connect to node 1") {
			return
		}

		assert.Len(t, node1.network.connectionManager.Peers(), 2)
		assert.Len(t, node2.network.connectionManager.Peers(), 2)
	})
}

func TestNetworkIntegration_NodeDIDAuthentication(t *testing.T) {
	t.Run("mutual auth", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)

		// Start 2 nodes: node1 and node2, where node1 specifies a node DID that node2 can't authenticate
		node1 := startNode(t, "node1", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node1"
		})
		node2 := startNode(t, "node2", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node2"
		})
		// Now connect node1 to node2 and wait for them to set up
		node1.network.connectionManager.Connect(nameToAddress(t, "node2"), did.MustParseDID("did:nuts:node2"), nil)

		test.WaitFor(t, func() (bool, error) {
			return len(node1.network.connectionManager.Peers()) == 1 && len(node2.network.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for node1 to connect to node2")
	})
	t.Run("node DID auth sent client (authenticated by server) fails", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)

		// Start 2 nodes: node1 and node2, where node1 specifies a node DID that node2 can't authenticate
		node1 := startNode(t, "node1", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node1"
		})
		node2 := startNode(t, "node2", testDirectory)

		// Set node DID to an unauthenticatable DID, such that authentication must fail
		malloryDID, _ := did.ParseDID("did:nuts:mallory")
		node1.network.nodeDIDResolver.(*transport.FixedNodeDIDResolver).NodeDID = *malloryDID

		// Now connect node1 to node2 and wait for them to set up
		node1.network.connectionManager.Connect(nameToAddress(t, "node2"), did.MustParseDID("did:nuts:node2"), nil)
		if !test.WaitFor(t, func() (bool, error) {
			diagnostics := node1.network.connectionManager.MappedDiagnostics()["addressbook"]
			connectorsStats := diagnostics()[0].(grpc.ContactsStats)
			// Assert we tried to connect at least once
			return connectorsStats[0].Attempts >= 1, nil
		}, defaultTimeout, "time-out while waiting for node 1 to try to connect") {
			return
		}

		// Assert there are no peers, because authentication failed
		assert.Empty(t, node1.network.connectionManager.Peers())
		assert.Empty(t, node2.network.connectionManager.Peers())
	})
	t.Run("node DID auth sent by server (authenticated by client) fails", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)

		// Start 2 nodes: node1 and node2, where node2 specifies a node DID that node1 can't authenticate
		node1 := startNode(t, "node1", testDirectory)
		node2 := startNode(t, "node2", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node2"
		})

		// Set node DID to an unauthenticatable DID, such that authentication must fail
		malloryDID, _ := did.ParseDID("did:nuts:mallory")
		node2.network.nodeDIDResolver.(*transport.FixedNodeDIDResolver).NodeDID = *malloryDID

		// Now connect node1 to node2 and wait for them to set up
		node1.network.connectionManager.Connect(nameToAddress(t, "node2"), did.MustParseDID("did:nuts:node2"), nil)
		if !test.WaitFor(t, func() (bool, error) {
			diagnostics := node1.network.connectionManager.MappedDiagnostics()["addressbook"]
			connectorsStats := diagnostics()[0].(grpc.ContactsStats)
			// Assert we tried to connect at least once
			return connectorsStats[0].Attempts >= 1, nil
		}, defaultTimeout, "time-out while waiting for node 1 to try to connect") {
			return
		}

		// Assert there are no peers, because authentication failed
		assert.Empty(t, node1.network.connectionManager.Peers())
		assert.Empty(t, node2.network.connectionManager.Peers())
	})
}

func TestNetworkIntegration_PrivateTransaction(t *testing.T) {
	t.Run("happy flow", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)
		key := nutsCrypto.NewTestKey("key")

		// Start 2 nodes: node1 and node2, node1 sends a private TX to node 2
		node1 := startNode(t, "node1", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node1"
		})
		node2 := startNode(t, "node2", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node2"
		})
		// Now connect node1 to node2 and wait for them to set up
		node1.network.connectionManager.Connect(nameToAddress(t, "node2"), did.MustParseDID("did:nuts:node2"), nil)

		test.WaitFor(t, func() (bool, error) {
			return len(node1.network.connectionManager.Peers()) == 1 && len(node2.network.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for node1 to connect to node2")

		node1DID, _ := node1.network.nodeDIDResolver.Resolve()
		node2DID, _ := node2.network.nodeDIDResolver.Resolve()
		tpl := TransactionTemplate(payloadType, []byte("private TX"), key).
			WithAttachKey().
			WithPrivate([]did.DID{node1DID, node2DID})
		tx, err := node1.network.CreateTransaction(audit.TestContext(), tpl)
		require.NoError(t, err)
		waitForTransaction(t, tx, "node2")

		// assert not only TX is transfered, but state is updates as well
		xor1, _ := node1.network.state.XOR(dag.MaxLamportClock)
		xor2, _ := node2.network.state.XOR(dag.MaxLamportClock)
		assert.Equal(t, xor1.String(), xor2.String())
	})

	t.Run("event received", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)
		key := nutsCrypto.NewTestKey("key")

		// Start 2 nodes: node1 and node2, node1 sends a private TX to node 2
		node1 := startNode(t, "node1", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node1"
		})
		node2 := startNode(t, "node2", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node2"
		})
		// Now connect node1 to node2 and wait for them to set up
		node1.network.connectionManager.Connect(nameToAddress(t, "node2"), did.MustParseDID("did:nuts:node2"), nil)

		test.WaitFor(t, func() (bool, error) {
			return len(node1.network.connectionManager.Peers()) == 1 && len(node2.network.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for node1 to connect to node2")

		// setup eventListener
		stream := node2.network.eventPublisher.GetStream(events.TransactionsStream)
		conn, _, err := node2.network.eventPublisher.Pool().Acquire(context.Background())
		require.NoError(t, err)
		defer conn.Close()
		var found []byte
		foundMutex := sync.Mutex{}
		_ = stream.Subscribe(conn, "TEST", "TRANSACTIONS.tx", func(msg *nats.Msg) {
			foundMutex.Lock()
			defer foundMutex.Unlock()
			found = msg.Data
			err := msg.Ack()
			require.NoError(t, err)
		})

		node1DID, _ := node1.network.nodeDIDResolver.Resolve()
		node2DID, _ := node2.network.nodeDIDResolver.Resolve()
		tpl := TransactionTemplate(payloadType, []byte("private TX"), key).
			WithAttachKey().
			WithPrivate([]did.DID{node1DID, node2DID})
		_, err = node1.network.CreateTransaction(audit.TestContext(), tpl)
		require.NoError(t, err)

		test.WaitFor(t, func() (bool, error) {
			foundMutex.Lock()
			defer foundMutex.Unlock()
			return len(found) > 0, nil
		}, 100*time.Millisecond, "timeout waiting for message")
	})

	t.Run("third node knows nothing", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)
		key := nutsCrypto.NewTestKey("key")

		// Start 2 nodes: node1 and node2, node1 sends a private TX to node 2
		node1 := startNode(t, "node1", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node1"
		})
		node2 := startNode(t, "node2", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node2"
		})
		node3 := startNode(t, "node3", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node3"
		})
		// Now connect node1 to node2 and wait for them to set up
		node2.network.connectionManager.Connect(nameToAddress(t, "node1"), did.MustParseDID("did:nuts:node1"), nil)
		node3.network.connectionManager.Connect(nameToAddress(t, "node1"), did.MustParseDID("did:nuts:node1"), nil)

		test.WaitFor(t, func() (bool, error) {
			return len(node1.network.connectionManager.Peers()) == 2, nil
		}, defaultTimeout, "time-out while waiting for nodes to connect")

		node1DID, _ := node1.network.nodeDIDResolver.Resolve()
		node2DID, _ := node2.network.nodeDIDResolver.Resolve()
		tpl := TransactionTemplate(payloadType, []byte("private TX"), key).
			WithAttachKey().
			WithPrivate([]did.DID{node1DID, node2DID})
		tx, err := node1.network.CreateTransaction(audit.TestContext(), tpl)
		require.NoError(t, err)
		arrived := test.WaitForNoFail(t, func() (bool, error) {
			mutex.Lock()
			defer mutex.Unlock()
			for _, receivedDoc := range receivedTransactions["node3"] {
				if tx.Ref().Equals(receivedDoc.Ref()) {
					return true, nil
				}
			}
			return false, nil
		}, 200*time.Millisecond)

		// check node 3 does not have the payload
		assert.False(t, arrived)
	})

	t.Run("three participants", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)
		key := nutsCrypto.NewTestKey("key")

		// Start 3 nodes: node1, node2 and node3. Node 1 sends a private TX to node 2 and node 3, which both should receive.
		node1 := startNode(t, "node1", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node1"
		})
		node2 := startNode(t, "node2", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node2"
		})
		node3 := startNode(t, "node3", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node3"
		})
		// Make a full mesh
		node1.network.connectionManager.Connect(nameToAddress(t, "node2"), did.MustParseDID("did:nuts:node2"), nil)
		node2.network.connectionManager.Connect(nameToAddress(t, "node3"), did.MustParseDID("did:nuts:node3"), nil)

		test.WaitFor(t, func() (bool, error) {
			return len(node1.network.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for nodes to connect")
		test.WaitFor(t, func() (bool, error) {
			return len(node2.network.connectionManager.Peers()) == 2, nil
		}, defaultTimeout, "time-out while waiting for nodes to connect")
		test.WaitFor(t, func() (bool, error) {
			return len(node3.network.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for nodes to connect")

		node1DID, _ := node1.network.nodeDIDResolver.Resolve()
		node2DID, _ := node2.network.nodeDIDResolver.Resolve()
		node3DID, _ := node3.network.nodeDIDResolver.Resolve()
		// Random order for PAL header
		pal := []did.DID{node1DID, node2DID, node3DID}
		rand.Shuffle(len(pal), func(i, j int) {
			pal[i], pal[j] = pal[j], pal[i]
		})
		tpl := TransactionTemplate(payloadType, []byte("private TX"), key).
			WithAttachKey().
			WithPrivate(pal)
		tx, err := node1.network.CreateTransaction(audit.TestContext(), tpl)
		require.NoError(t, err)
		waitForTransaction(t, tx, "node1", "node2", "node3")
	})

	t.Run("large amount of private transactions", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)
		key := nutsCrypto.NewTestKey("key")

		// Start 2 nodes: node1 and node2, node1 sends a private TX to node 2
		node1 := startNode(t, "node1", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node1"
		})
		node2 := startNode(t, "node2", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node2"
		})

		// create some transactions
		node1DID, _ := node1.network.nodeDIDResolver.Resolve()
		node2DID, _ := node2.network.nodeDIDResolver.Resolve()
		for i := 0; i < 10; i++ {
			tpl := TransactionTemplate(payloadType, []byte(fmt.Sprintf("private TX%d", i)), key).
				WithAttachKey().
				WithPrivate([]did.DID{node1DID, node2DID})
			_, err := node1.network.CreateTransaction(audit.TestContext(), tpl)
			require.NoError(t, err)
		}

		// Now connect node1 to node2 and wait for them to set up
		node1.network.connectionManager.Connect(nameToAddress(t, "node2"), did.MustParseDID("did:nuts:node2"), nil)

		test.WaitFor(t, func() (bool, error) {
			return len(node1.network.connectionManager.Peers()) == 1 && len(node2.network.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for node1 to connect to node2")

		test.WaitFor(t, func() (bool, error) {
			xor1, _ := node1.network.state.XOR(10)
			xor2, _ := node2.network.state.XOR(10)
			return xor1.Equals(xor2), nil
		}, 10*time.Second, "%s: time-out while waiting for transactions", node2.network.Name())
	})

	t.Run("TLS disabled", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)
		key := nutsCrypto.NewTestKey("key")

		// Start 2 nodes: node1 and node2, node1 sends a private TX to node 2
		node1 := startNode(t, "noTLS1", testDirectory, func(serverConfig *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node1"
			serverConfig.LegacyTLS.Enabled = false
			serverConfig.Strictmode = false
		})
		node2 := startNode(t, "noTLS2", testDirectory, func(serverConfig *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node2"
			serverConfig.LegacyTLS.Enabled = false
			serverConfig.Strictmode = false
		})
		// Now connect node1 to node2 and wait for them to set up
		node1.network.connectionManager.Connect(nameToAddress(t, "noTLS2"), did.MustParseDID("did:nuts:node2"), nil)

		test.WaitFor(t, func() (bool, error) {
			return len(node1.network.connectionManager.Peers()) == 1 && len(node2.network.connectionManager.Peers()) == 1, nil
		}, defaultTimeout, "time-out while waiting for node1 to connect to node2")

		node1DID, _ := node1.network.nodeDIDResolver.Resolve()
		node2DID, _ := node2.network.nodeDIDResolver.Resolve()
		tpl := TransactionTemplate(payloadType, []byte("private TX"), key).
			WithAttachKey().
			WithPrivate([]did.DID{node1DID, node2DID})
		tx, err := node1.network.CreateTransaction(audit.TestContext(), tpl)
		require.NoError(t, err)
		waitForTransaction(t, tx, "noTLS2")

		// assert not only TX is transfered, but state is updates as well
		xor1, _ := node1.network.state.XOR(dag.MaxLamportClock)
		xor2, _ := node2.network.state.XOR(dag.MaxLamportClock)
		assert.Equal(t, xor1.String(), xor2.String())
	})

	t.Run("spoofing peerID does not change the recipient of a response message", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		resetIntegrationTest(t)
		key := nutsCrypto.NewTestKey("key")

		// Start 2 nodes: node1 and node2, node1 sends a private TX to node 2
		node1 := startNode(t, "node1", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node1"
		})
		node2 := startNode(t, "node2", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node2"
		})
		eve := startNode(t, "node3", testDirectory, func(_ *core.ServerConfig, cfg *Config) {
			cfg.NodeDID = "did:nuts:node3"
		})
		grpc.SetPeerID(t, eve.network.connectionManager, node2.network.peerID) // eve uses node2's peerID

		// Let eve connect first, so she is the first in the node1's connection list
		eve.network.connectionManager.Connect(nameToAddress(t, "node1"), did.MustParseDID("did:nuts:node1"), nil)
		// eve also must connect to node2 so the gossip propagates from node1 via eve to node2 (gossipManager ignores duplicate peerIDs). Could be any other peer than node1 though.
		eve.network.connectionManager.Connect(nameToAddress(t, "node2"), did.MustParseDID("did:nuts:node2"), nil)
		test.WaitFor(t, func() (bool, error) {
			return len(eve.network.connectionManager.Peers()) == 2, nil
		}, defaultTimeout, "time-out while waiting for nodes to connect")

		// Connect node1 and node2
		node2.network.connectionManager.Connect(nameToAddress(t, "node1"), did.MustParseDID("did:nuts:node1"), nil)
		test.WaitFor(t, func() (bool, error) {
			return len(node2.network.connectionManager.Peers()) == 2, nil // make sure node2 has enough peers to learn about the private Tx
		}, defaultTimeout, "time-out while waiting for nodes to connect")

		node1DID, _ := node1.network.nodeDIDResolver.Resolve()
		node2DID, _ := node2.network.nodeDIDResolver.Resolve()
		tpl := TransactionTemplate(payloadType, []byte("private TX"), key).
			WithAttachKey().
			WithPrivate([]did.DID{node1DID, node2DID})
		tx, err := node1.network.CreateTransaction(audit.TestContext(), tpl)
		require.NoError(t, err)
		arrivedAtNode2 := test.WaitForNoFail(t, func() (bool, error) {
			mutex.Lock()
			defer mutex.Unlock()
			for _, receivedDoc := range receivedTransactions["node2"] {
				if tx.Ref().Equals(receivedDoc.Ref()) {
					return true, nil
				}
			}
			return false, nil
		}, time.Second)
		arrivedAtEve := test.WaitForNoFail(t, func() (bool, error) {
			mutex.Lock()
			defer mutex.Unlock()
			for _, receivedDoc := range receivedTransactions["node3"] {
				if tx.Ref().Equals(receivedDoc.Ref()) {
					return true, nil
				}
			}
			return false, nil
		}, time.Second)

		// make sure eve does not have the payload
		assert.False(t, arrivedAtEve)
		assert.True(t, arrivedAtNode2)
	})
}

func TestNetworkIntegration_OutboundConnection11Reconnects(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	resetIntegrationTest(t)

	// Given node1 and node2
	// Given node1 connects to node2
	// When node2 shuts down
	// Then node1 isn't connected to node2
	// When node2 starts again
	// Then node1 should reconnect to node2
	node1 := startNode(t, "node1", testDirectory)
	node2 := startNode(t, "node2", testDirectory)

	// Now connect node1 to node2 and wait for them to set up
	node1.network.connectionManager.Connect(nameToAddress(t, "node2"), did.DID{}, nil)
	if !test.WaitFor(t, func() (bool, error) {
		return len(node1.network.connectionManager.Peers()) == 1 && len(node2.network.connectionManager.Peers()) == 1, nil
	}, defaultTimeout, "time-out while waiting for node 1 and 2 to be connected") {
		return
	}

	// Now shut down node2 and for wait node1 to notice it
	node2.shutdown()
	if !test.WaitFor(t, func() (bool, error) {
		return len(node1.network.connectionManager.Peers()) == 0, nil
	}, defaultTimeout, "time-out while waiting for node 1 to notice shut down node") {
		return
	}

	// Now start node2 again, node1 should reconnect
	node2 = startNode(t, "node2", testDirectory) // important to start a new instance, otherwise PeerID isn't regenerated
	if !test.WaitFor(t, func() (bool, error) {
		return len(node1.network.connectionManager.Peers()) == 1, nil
	}, defaultTimeout, "time-out while waiting for node 1 to reconnect to node 2") {
		return
	}

	// Bug: outbound peer.Address is empty after reconnect
	assert.NotEmpty(t, node1.network.connectionManager.Peers()[0].Address)
	assert.NotEmpty(t, node1.network.connectionManager.Peers()[0].ID)
}

func TestNetworkIntegration_AddedTransactionsAsEvents(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	resetIntegrationTest(t)

	node1 := startNode(t, "node1", testDirectory)
	node2 := startNode(t, "node2", testDirectory)

	// Now connect node1 to node2 and wait for them to set up
	node1.network.connectionManager.Connect(nameToAddress(t, "node2"), did.DID{}, nil)
	if !test.WaitFor(t, func() (bool, error) {
		return len(node1.network.connectionManager.Peers()) == 1 && len(node2.network.connectionManager.Peers()) == 1, nil
	}, defaultTimeout, "time-out while waiting for node 1 and 2 to be connected") {
		return
	}

	// setup eventListener
	stream := node2.network.eventPublisher.GetStream(events.TransactionsStream)
	conn, _, err := node2.network.eventPublisher.Pool().Acquire(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	var found []byte
	foundMutex := sync.Mutex{}
	_ = stream.Subscribe(conn, "TEST", "TRANSACTIONS.tx", func(msg *nats.Msg) {
		foundMutex.Lock()
		defer foundMutex.Unlock()
		found = msg.Data
		err := msg.Ack()
		require.NoError(t, err)
	})

	// add a transaction
	key := nutsCrypto.NewTestKey("key")
	addTransactionAndWaitForItToArrive(t, "payload", key, node1)

	test.WaitFor(t, func() (bool, error) {
		foundMutex.Lock()
		defer foundMutex.Unlock()
		return len(found) > 0, nil
	}, time.Second, "timeout waiting for message")

	event := events.TransactionWithPayload{}
	_ = json.Unmarshal(found, &event)

	assert.Equal(t, uint32(0), event.Transaction.Clock())
	assert.Equal(t, "payload", string(event.Payload))
}

func TestNetworkIntegration_TLSOffloading(t *testing.T) {
	resetIntegrationTest(t)

	t.Run("server offloads incoming TLS", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			testDirectory := io.TestDirectory(t)
			// Start server node (node1)
			node1 := startNode(t, "node1", testDirectory, func(serverCfg *core.ServerConfig, cfg *Config) {
				serverCfg.TLS.Offload = core.OffloadIncomingTLS
				serverCfg.TLS.ClientCertHeaderName = "client-cert"
			})

			// Create client (node2) that connects to server node
			grpcConn, err := grpcLib.Dial(nameToAddress(t, "node1"), grpcLib.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer grpcConn.Close()
			ctx := context.Background()
			outgoingMD := metadata.MD{}
			outgoingMD.Set("peerID", "client")
			outgoingMD.Set("nodeDID", "did:nuts:node2")
			// Load client cert and set as HTTP request header, as will be done by a TLS terminator
			clientCertBytes, err := os.ReadFile("test/certificate-and-key.pem")
			require.NoError(t, err)

			xffHeader := "8.8.8.8,8.8.4.4,127.0.0.1"
			outgoingMD.Set("X-Forwarded-For", xffHeader)
			outgoingMD.Set("client-cert", url.QueryEscape(string(clientCertBytes)))
			outgoingContext := metadata.NewOutgoingContext(ctx, outgoingMD)
			client := v2.NewProtocolClient(grpcConn)
			result, err := client.Stream(outgoingContext)
			require.NoError(t, err)

			// Assert connection is OK
			msg, err := result.Recv()
			assert.NoError(t, err)
			assert.NotNil(t, msg)
			assert.Contains(t, node1.network.Diagnostics()[0].String(), "client(did:nuts:node2)@8.8.4.4")
		})
		t.Run("authentication fails", func(t *testing.T) {
			testDirectory := io.TestDirectory(t)
			// Start server node (node1)
			_ = startNode(t, "node1", testDirectory, func(serverCfg *core.ServerConfig, cfg *Config) {
				serverCfg.TLS.Offload = core.OffloadIncomingTLS
				serverCfg.TLS.ClientCertHeaderName = "client-cert"
			})

			// Create client (node2) that connects to server node
			grpcConn, err := grpcLib.Dial(nameToAddress(t, "node1"), grpcLib.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			ctx := context.Background()
			outgoingMD := metadata.MD{}
			outgoingMD.Set("peerID", "client")
			outgoingMD.Set("nodeDID", "did:nuts:node2")
			outgoingContext := metadata.NewOutgoingContext(ctx, outgoingMD)
			client := v2.NewProtocolClient(grpcConn)
			result, err := client.Stream(outgoingContext)
			require.NoError(t, err)

			// Assert connection is rejected
			msg, err := result.Recv()
			assert.EqualError(t, err, "rpc error: code = Unauthenticated desc = TLS client certificate authentication failed")
			assert.Nil(t, msg)
		})
	})
}

func resetIntegrationTest(t *testing.T) {
	// in an integration test we want everything to work as intended, disable test speedup and re-enable file sync for bbolt
	defaultBBoltOptions.NoSync = false
	mutex.Lock()
	defer mutex.Unlock()

	receivedTransactions = make(map[string][]dag.Transaction, 0)

	didStore = didstore.NewTestStore(t)
	keyStore = nutsCrypto.NewMemoryCryptoInstance()

	// Write DID Document for node1
	writeDIDDocument := func(subject string) {
		nodeDID := did.MustParseDID(subject)
		document := did.Document{ID: nodeDID}
		kid := nodeDID
		kid.Fragment = "key-1"
		key, _ := keyStore.New(audit.TestContext(), func(_ crypto.PublicKey) (string, error) {
			return kid.String(), nil
		})
		verificationMethod, _ := did.NewVerificationMethod(kid, ssi.JsonWebKey2020, nodeDID, key.Public())
		document.VerificationMethod.Add(verificationMethod)
		document.KeyAgreement.Add(verificationMethod)
		document.CapabilityInvocation.Add(verificationMethod)
		document.Service = []did.Service{{
			Type:            transport.NutsCommServiceType,
			ServiceEndpoint: "grpc://nuts.nl:5555", // Must match TLS SAN DNSName
		}}
		docBytes, _ := json.Marshal(document)
		tx, _, _ := dag.CreateTestTransactionEx(0, hash.SHA256Sum(docBytes), nil)
		err := didStore.Add(document, didstore.Transaction{
			Clock:       tx.Clock(),
			PayloadHash: tx.PayloadHash(),
			Previous:    tx.Previous(),
			Ref:         tx.Ref(),
			SigningTime: tx.SigningTime(),
		})
		require.NoError(t, err)
	}
	writeDIDDocument("did:nuts:node1")
	writeDIDDocument("did:nuts:node2")
	writeDIDDocument("did:nuts:node3")
}

func addTransactionAndWaitForItToArrive(t *testing.T, payload string, key nutsCrypto.Key, sender node, receivers ...string) bool {
	expectedTransaction, err := sender.network.CreateTransaction(audit.TestContext(), TransactionTemplate(payloadType, []byte(payload), key).WithAttachKey())
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
		}, defaultTimeout, "time-out while waiting for transaction to arrive at %s", receiver) {
			return false
		}
	}
	return true
}

func startNode(t *testing.T, name string, testDirectory string, opts ...func(serverConfig *core.ServerConfig, moduleConfig *Config)) node {
	log.Logger().Infof("Starting node: %s", name)
	serverConfig := core.NewServerConfig()
	serverConfig.Verbosity = "debug"
	_ = serverConfig.Load(core.FlagSet())
	serverConfig.Datadir = path.Join(testDirectory, name)
	serverConfig.LegacyTLS.Enabled = true
	serverConfig.TLS.CertFile = "test/certificate-and-key.pem"
	serverConfig.TLS.CertKeyFile = "test/certificate-and-key.pem"
	serverConfig.TLS.TrustStoreFile = "test/truststore.pem"

	// Create Network instance
	config := Config{
		GrpcAddr: fmt.Sprintf("localhost:%d", nameToPort(t, name)),
		ProtocolV2: v2.Config{
			GossipInterval:      50,
			PayloadRetryDelay:   50 * time.Millisecond,
			DiagnosticsInterval: int(time.Minute.Milliseconds()),
		},
		ConnectionTimeout: 5000,
	}
	for _, f := range opts {
		f(serverConfig, &config)
	}

	eventPublisher := events.NewManager()
	if err := eventPublisher.(core.Configurable).Configure(*serverConfig); err != nil {
		t.Fatal(err)
	}
	if err := eventPublisher.(core.Runnable).Start(); err != nil {
		t.Fatal(err)
	}

	storeProvider := storage.StaticKVStoreProvider{
		Store: storage.CreateTestBBoltStore(t, serverConfig.Datadir+"/test.db"),
	}

	instance := &Network{
		config:              config,
		didDocumentResolver: didservice.Resolver{Store: didStore},
		didDocumentFinder:   didservice.Finder{Store: didStore},
		keyStore:            keyStore,
		keyResolver:         didservice.KeyResolver{Store: didStore},
		nodeDIDResolver:     &transport.FixedNodeDIDResolver{},
		eventPublisher:      eventPublisher,
		storeProvider:       &storeProvider,
	}

	if err := instance.Configure(*serverConfig); err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	_ = instance.Subscribe(t.Name(), func(event dag.Event) (bool, error) {
		mutex.Lock()
		defer mutex.Unlock()
		log.Logger().Infof("Transaction %s arrived at %s", string(event.Payload), name)
		receivedTransactions[name] = append(receivedTransactions[name], event.Transaction)
		return true, nil
	}, WithSelectionFilter(func(event dag.Event) bool {
		return event.Type == dag.PayloadEventType
	}))

	result := node{
		network:        instance,
		eventPublisher: eventPublisher,
	}
	t.Cleanup(func() {
		result.shutdown()
	})
	return result
}

type node struct {
	network        *Network
	eventPublisher events.Event
}

func (n node) shutdown() {
	kvStore, _ := n.network.storeProvider.GetKVStore(ModuleName, storage.PersistentStorageClass)
	err := kvStore.Close(context.Background())
	if err != nil {
		panic(err)
	}
	_ = n.network.Shutdown()
	_ = n.eventPublisher.(core.Runnable).Shutdown()
}

func nameToPort(t *testing.T, name string) int {
	return int(crc32.ChecksumIEEE([]byte(t.Name()+"/"+name))%9000 + 1000)
}

func nameToAddress(t *testing.T, name string) string {
	return fmt.Sprintf("localhost:%d", nameToPort(t, name))
}
