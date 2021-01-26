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
	"crypto"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/nuts-foundation/nuts-node/network/proto"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"hash/crc32"
	"os"
	"path"
	"sync"
	"testing"
	"time"
)

const defaultTimeout = 2 * time.Second
const documentType = "test/document"

var mutex = sync.Mutex{}
var receivedDocuments = make(map[string][]dag.Document, 0)

func TestNetwork(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	expectedDocLogSize := 0

	// Start 3 nodes: bootstrap, node1 and node2. Node 1 and 2 connect to the bootstrap node and should discover
	// each other that way.
	bootstrap, err := startNode("bootstrap", path.Join(testDirectory, "bootstrap"))
	if !assert.NoError(t, err) {
		return
	}
	node1, err := startNode("node1", path.Join(testDirectory, "node1"))
	if !assert.NoError(t, err) {
		return
	}
	node1.p2pNetwork.ConnectToPeer(nameToAddress("bootstrap"))
	node2, err := startNode("node2", path.Join(testDirectory, "node2"))
	if !assert.NoError(t, err) {
		return
	}
	node2.p2pNetwork.ConnectToPeer(nameToAddress("bootstrap"))
	stop := func() {
		node2.Shutdown()
		node1.Shutdown()
		bootstrap.Shutdown()
	}

	// Wait until nodes are connected
	if !waitFor(t, func() (bool, error) {
		return len(node1.p2pNetwork.Peers()) == 1 && len(node2.p2pNetwork.Peers()) == 1, nil
	}, defaultTimeout, "time-out while waiting for node 1 and 2 to have 2 peers") {
		stop()
		return
	}

	// Publish first document on node1 and we expect in to come out on node2 and bootstrap
	if !addDocumentAndWaitForItToArrive(t, "doc1", node1, "node2", "bootstrap") {
		stop()
		return
	}
	expectedDocLogSize++

	// Now the graph has a root, and node2 can publish a document
	if !addDocumentAndWaitForItToArrive(t, "doc2", node2, "node1", "bootstrap") {
		stop()
		return
	}
	expectedDocLogSize++

	// Now assert that all nodes have received all documents
	waitForDocuments := func(node string, graph dag.DAG) bool {
		return waitFor(t, func() (bool, error) {
			if docs, err := graph.All(); err != nil {
				return false, err
			} else {
				return len(docs) == expectedDocLogSize, nil
			}
		}, defaultTimeout, "%s: time-out while waiting for %d documents", node, expectedDocLogSize)
	}
	waitForDocuments("bootstrap", bootstrap.documentGraph)
	waitForDocuments("node 1", node1.documentGraph)
	waitForDocuments("node 2", node2.documentGraph)

	// Can we request the diagnostics?
	fmt.Printf("%v\n", bootstrap.Diagnostics())
	fmt.Printf("%v\n", node1.Diagnostics())
	fmt.Printf("%v\n", node2.Diagnostics())
}

func addDocumentAndWaitForItToArrive(t *testing.T, payload string, sender *NetworkEngine, receivers ...string) bool {
	expectedDocument, err := sender.CreateDocument(documentType, []byte(payload), "key", true, time.Now())
	if !assert.NoError(t, err) {
		return true
	}
	for _, receiver := range receivers {
		if !waitFor(t, func() (bool, error) {
			mutex.Lock()
			defer mutex.Unlock()
			for _, receivedDoc := range receivedDocuments[receiver] {
				if expectedDocument.Ref().Equals(receivedDoc.Ref()) {
					return true, nil
				}
			}
			return false, nil
		}, 2*time.Second, "time-out while waiting for document to arrive at %s", receiver) {
			return false
		}
	}
	return true
}

func startNode(name string, directory string) (*NetworkEngine, error) {
	log.Logger().Infof("Starting node: %s", name)
	os.MkdirAll(directory, os.ModePerm)
	logrus.SetLevel(logrus.DebugLevel)
	core.NutsConfig().Load(&cobra.Command{})
	mutex.Lock()
	mutex.Unlock()
	// Initialize crypto instance
	cryptoInstance := nutsCrypto.Instance()
	cryptoInstance.Config = nutsCrypto.Config{Fspath: directory}
	if err := cryptoInstance.Configure(); err != nil {
		return nil, err
	}
	nutsCrypto.Instance().New(func(key crypto.PublicKey) (string, error) {
		return "key", nil
	})
	// Create NetworkEngine instance
	instance := &NetworkEngine{
		p2pNetwork: p2p.NewP2PNetwork(),
		protocol:   proto.NewProtocol(),
		keyStore:   cryptoInstance,
		Config: Config{
			GrpcAddr:             fmt.Sprintf(":%d", nameToPort(name)),
			DatabaseFile:         path.Join(directory, "network.db"),
			PublicAddr:           fmt.Sprintf("localhost:%d", nameToPort(name)),
			CertFile:             "test/certificate-and-key.pem",
			CertKeyFile:          "test/certificate-and-key.pem",
			TrustStoreFile:       "test/truststore.pem",
			EnableTLS:            true,
			AdvertHashesInterval: 500,
		},
	}
	if err := instance.Configure(); err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		return nil, err
	}
	instance.Subscribe(documentType, func(document dag.Document, payload []byte) error {
		mutex.Lock()
		defer mutex.Unlock()
		println("document", string(payload), "arrived at", name)
		receivedDocuments[name] = append(receivedDocuments[name], document)
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
