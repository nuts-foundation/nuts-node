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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"hash/crc32"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/nuts-foundation/nuts-node/network/proto"
	"github.com/nuts-foundation/nuts-node/test/io"
)

const defaultTimeout = 2 * time.Second
const payloadType = "test/transaction"

var mutex = sync.Mutex{}
var receivedTransactions = make(map[string][]dag.SubscriberTransaction, 0)

func TestNetworkIntegration_HappyFlow(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	resetIntegrationTest(testDirectory)
	cryptoInstance := nutsCrypto.NewTestCryptoInstance(testDirectory)
	key, _, _ := cryptoInstance.New(func(key crypto.PublicKey) (string, error) {
		return "key", nil
	})
	expectedDocLogSize := 0

	// Start 3 nodes: bootstrap, node1 and node2. Node 1 and 2 connect to the bootstrap node and should discover
	// each other that way.
	bootstrap, err := startNode("bootstrap", path.Join(testDirectory, "bootstrap"), cryptoInstance)
	if !assert.NoError(t, err) {
		return
	}
	node1, err := startNode("node1", path.Join(testDirectory, "node1"), cryptoInstance)
	if !assert.NoError(t, err) {
		return
	}
	node1.p2pNetwork.ConnectToPeer(nameToAddress("bootstrap"))
	node2, err := startNode("node2", path.Join(testDirectory, "node2"), cryptoInstance)
	if !assert.NoError(t, err) {
		return
	}
	node2.p2pNetwork.ConnectToPeer(nameToAddress("bootstrap"))
	defer func() {
		node2.Shutdown()
		node1.Shutdown()
		bootstrap.Shutdown()
	}()

	// Wait until nodes are connected
	if !waitFor(t, func() (bool, error) {
		return len(node1.p2pNetwork.Peers()) == 1 && len(node2.p2pNetwork.Peers()) == 1, nil
	}, defaultTimeout, "time-out while waiting for node 1 and 2 to have 2 peers") {
		return
	}

	// Publish first transaction on node1 and we expect in to come out on node2 and bootstrap
	if !addTransactionAndWaitForItToArrive(t, "doc1", key, node1, "node2", "bootstrap") {
		return
	}
	expectedDocLogSize++

	// Now the graph has a root, and node2 can publish a transaction
	if !addTransactionAndWaitForItToArrive(t, "doc2", key, node2, "node1", "bootstrap") {
		return
	}
	expectedDocLogSize++

	// Now assert that all nodes have received all transactions
	waitForTransactions := func(node string, graph dag.DAG) bool {
		return waitFor(t, func() (bool, error) {
			if docs, err := graph.All(); err != nil {
				return false, err
			} else {
				return len(docs) == expectedDocLogSize, nil
			}
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

func TestNetworkIntegration_SignatureIncorrect(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	resetIntegrationTest(testDirectory)

	cryptoInstance := nutsCrypto.NewTestCryptoInstance(testDirectory)
	key, _, _ := cryptoInstance.New(func(key crypto.PublicKey) (string, error) {
		return "key", nil
	})

	// Start node 1 and node 2. Node 1 adds 3 transactions:
	// 1. first transaction is OK, must be received
	// 2. second transaction has an invalid signature, must be rejected
	// 3. third transaction is OK, must be  received (to deal with timing issues)
	node1, err := startNode("node1", path.Join(testDirectory, "node1"), cryptoInstance)
	if !assert.NoError(t, err) {
		return
	}
	node2, err := startNode("node2", path.Join(testDirectory, "node2"), cryptoInstance)
	if !assert.NoError(t, err) {
		return
	}
	node2.p2pNetwork.ConnectToPeer(nameToAddress("node1"))
	defer func() {
		node2.Shutdown()
		node1.Shutdown()
	}()
	// Send first OK transaction and wait for it to be received
	if !addTransactionAndWaitForItToArrive(t, "first transaction", key, node1, "node2") {
		return
	}

	// Send second transaction which has an invalid signature (included JWK is incorrect), should be rejected
	attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte("second transaction")
	unsignedTransaction, _ := dag.NewTransaction(hash.SHA256Sum(payload), payloadType, []hash.SHA256Hash{receivedTransactions["node2"][0].Ref()})
	craftedTransaction, _ := dag.NewAttachedJWKTransactionSigner(cryptoInstance, "key", attackerKey.PublicKey).Sign(unsignedTransaction, time.Now())
	node1.payloadStore.WritePayload(hash.SHA256Sum(payload), payload)
	_ = node1.graph.Add(craftedTransaction)
	// Send third OK transaction
	if !addTransactionAndWaitForItToArrive(t, "third transaction", key, node2, "node1") {
		return
	}
	// Assert node2 only processed the first and last transaction, node1 all 3
	assert.Len(t, receivedTransactions["node2"], 2)
	assert.Len(t, receivedTransactions["node1"], 3)
	for _, d := range receivedTransactions["node2"] {
		if d.Ref().Equals(craftedTransaction.Ref()) {
			t.Error("Node 2 processed the crafted transaction.")
		}
	}
}

func resetIntegrationTest(testDirectory string) {
	receivedTransactions = make(map[string][]dag.SubscriberTransaction, 0)
}

func addTransactionAndWaitForItToArrive(t *testing.T, payload string, key crypto.PublicKey, sender *Network, receivers ...string) bool {
	expectedTransaction, err := sender.CreateTransaction(payloadType, []byte(payload), "key", key, time.Now())
	if !assert.NoError(t, err) {
		return true
	}
	for _, receiver := range receivers {
		if !waitFor(t, func() (bool, error) {
			mutex.Lock()
			defer mutex.Unlock()
			for _, receivedDoc := range receivedTransactions[receiver] {
				if expectedTransaction.Ref().Equals(receivedDoc.Ref()) {
					return true, nil
				}
			}
			return false, nil
		}, 2*time.Second, "time-out while waiting for transaction to arrive at %s", receiver) {
			return false
		}
	}
	return true
}

func startNode(name string, directory string, keyStore nutsCrypto.KeyStore) (*Network, error) {
	log.Logger().Infof("Starting node: %s", name)
	logrus.SetLevel(logrus.DebugLevel)
	core.NewServerConfig().Load(&cobra.Command{})
	mutex.Lock()
	mutex.Unlock()
	// Create Network instance
	instance := &Network{
		p2pNetwork: p2p.NewP2PNetwork(),
		protocol:   proto.NewProtocol(),
		keyStore:   keyStore,
		config: Config{
			GrpcAddr:             fmt.Sprintf(":%d", nameToPort(name)),
			PublicAddr:           fmt.Sprintf("localhost:%d", nameToPort(name)),
			CertFile:             "test/certificate-and-key.pem",
			CertKeyFile:          "test/certificate-and-key.pem",
			TrustStoreFile:       "test/truststore.pem",
			EnableTLS:            true,
			AdvertHashesInterval: 500,
		},
	}
	if err := instance.Configure(core.ServerConfig{Datadir: directory}); err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		return nil, err
	}
	instance.Subscribe(payloadType, func(transaction dag.SubscriberTransaction, payload []byte) error {
		mutex.Lock()
		defer mutex.Unlock()
		log.Logger().Infof("transaction %s arrived at %s", string(payload), name)
		receivedTransactions[name] = append(receivedTransactions[name], transaction)
		return nil
	})
	return instance, nil
}

func nameToPort(name string) int {
	return int(crc32.ChecksumIEEE([]byte(name))%9000 + 1000)
}

func nameToAddress(name string) string {
	return fmt.Sprintf("localhost:%d", nameToPort(name))
}

type predicate func() (bool, error)

func waitFor(t *testing.T, p predicate, timeout time.Duration, message string, msgArgs ...interface{}) bool {
	deadline := time.Now().Add(timeout)
	for {
		b, err := p()
		if !assert.NoError(t, err) {
			return false
		}
		if b {
			return true
		}
		if time.Now().After(deadline) {
			assert.Fail(t, fmt.Sprintf(message, msgArgs...))
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}
