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

package v1

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/p2p"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/store"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"go.etcd.io/bbolt"
	"hash/crc32"
	"io/fs"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/test/io"
)

const integrationTestTimeout = 10 * time.Second
const integrationTestPayloadType = "foo/bar"

// TestProtocolV1_MissingPayloads tests whether TransactionList messages are paginated when the transactions on the DAG
// exceed Protobuf's max message size.
func TestProtocolV1_MissingPayloads(t *testing.T) {
	node1 := startNode(t, "node1")
	node2 := startNode(t, "node2", func(config *Config) {
		config.CollectMissingPayloadsInterval = 50
	})

	// Create 2 transactions on node 1; TX0 and TX1, only writing payload for TX0
	// Then connect node 2 which should notice the payload of TX1 is missing.
	// Then write the payload to the store on node 1, which should then be queried by node 2
	tx0Root, _, _ := dag.CreateTestTransaction(1)
	// TX 0
	err := node1.payloadStore.WritePayload(context.Background(), tx0Root.PayloadHash(), []byte{1, 2, 3})
	if !assert.NoError(t, err) {
		return
	}
	err = node1.graph.Add(context.Background(), tx0Root)
	if !assert.NoError(t, err) {
		return
	}
	// TX 1
	tx1, _, _ := dag.CreateTestTransaction(2, tx0Root.Ref())
	err = node1.graph.Add(context.Background(), tx1)
	if !assert.NoError(t, err) {
		return
	}

	node2.connectionManager.Connect(
		nameToAddress("node1"))
	// Wait until nodes are connected
	if !test.WaitFor(t, func() (bool, error) {
		return len(node1.connectionManager.Peers()) == 1 && len(node2.connectionManager.Peers()) == 1, nil
	}, integrationTestTimeout, "time-out while waiting for node 1 and 2 to have 2 peers") {
		return
	}

	// Wait for TX0 to arrive
	test.WaitFor(t, func() (bool, error) {
		return node2.countTXs() == 1, nil
	}, integrationTestTimeout, "node2 didn't receive all transactions")

	// Now write the payload, node 2 should broadcast query node 1 for TX1's payload which it now has
	err = node1.payloadStore.WritePayload(context.Background(), tx1.PayloadHash(), []byte{3, 2, 1})
	if !assert.NoError(t, err) {
		return
	}
	test.WaitFor(t, func() (bool, error) {
		return node2.countTXs() == 2, nil
	}, integrationTestTimeout, "node2 didn't receive all transactions")
}

// TestProtocolV1_Pagination tests whether TransactionList messages are paginated when the transactions on the DAG
// exceed Protobuf's max message size.
func TestProtocolV1_Pagination(t *testing.T) {
	p2p.MaxMessageSizeInBytes = 4 * 1024 // 4kb
	const numberOfTransactions = 19      // 20 transactions equals +/- 12.6kb (which exceeds the set limit of 10kb)

	node1 := startNode(t, "pagination_node1")
	node2 := startNode(t, "pagination_node2")

	t.Logf("Creating %d transactions...", numberOfTransactions)
	rootTX, _, _ := dag.CreateTestTransaction(1)
	err := node1.graph.Add(context.Background(), rootTX)
	if !assert.NoError(t, err) {
		return
	}
	_ = node1.payloadStore.WritePayload(context.Background(), rootTX.PayloadHash(), []byte{2, 2, 2})
	prev := rootTX
	for i := 0; i < numberOfTransactions-1; i++ { // minus 1 to subtract root TX
		tx, _, _ := dag.CreateTestTransaction(uint32(i+2), prev.Ref())
		err := node1.graph.Add(context.Background(), tx)
		if !assert.NoError(t, err) {
			return
		}
		_ = node1.payloadStore.WritePayload(context.Background(), tx.PayloadHash(), []byte{1, 2, 3})
		prev = tx
	}

	node2.connectionManager.Connect(nameToAddress("pagination_node1"))
	// Wait until nodes are connected
	if !test.WaitFor(t, func() (bool, error) {
		return len(node1.connectionManager.Peers()) == 1 && len(node2.connectionManager.Peers()) == 1, nil
	}, integrationTestTimeout, "time-out while waiting for node 1 and 2 to have a peer") {
		return
	}

	test.WaitFor(t, func() (bool, error) {
		txs := node2.countTXs()
		t.Logf("received %d transactions", txs)
		return txs == numberOfTransactions, nil
	}, 10*time.Second, "node2 didn't receive all transactions")
}

type integrationTestContext struct {
	protocol          *protocolV1
	receivedTXs       []dag.Transaction
	mux               *sync.Mutex
	graph             dag.DAG
	payloadStore      dag.PayloadStore
	connectionManager transport.ConnectionManager
}

func (i *integrationTestContext) countTXs() int {
	i.mux.Lock()
	defer i.mux.Unlock()
	return len(i.receivedTXs)
}

func startNode(t *testing.T, name string, configurers ...func(config *Config)) *integrationTestContext {
	log.Logger().Infof("Starting node: %s", name)
	logrus.SetLevel(logrus.DebugLevel)

	testDirectory := io.TestDirectory(t)

	db, err := bbolt.Open(path.Join(testDirectory, "dag.db"), fs.ModePerm, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &integrationTestContext{
		mux: &sync.Mutex{},
	}

	ctx.graph = dag.NewBBoltDAG(db)
	ctx.payloadStore = dag.NewBBoltPayloadStore(db)
	publisher := dag.NewReplayingDAGPublisher(ctx.payloadStore, ctx.graph)
	publisher.Subscribe(integrationTestPayloadType, func(tx dag.Transaction, payload []byte) error {
		log.Logger().Infof("transaction %s arrived at %s", string(payload), name)
		ctx.mux.Lock()
		defer ctx.mux.Unlock()
		ctx.receivedTXs = append(ctx.receivedTXs, tx)
		return nil
	})
	publisher.Start()

	cfg := &Config{
		AdvertHashesInterval:      500,
		AdvertDiagnosticsInterval: 5000,
	}
	for _, c := range configurers {
		c(cfg)
	}
	peerID := transport.PeerID(name)
	listenAddress := fmt.Sprintf("localhost:%d", nameToPort(name))
	ctx.protocol = New(*cfg, ctx.graph, publisher, ctx.payloadStore, dummyDiagnostics).(*protocolV1)

	authenticator := grpc.NewTLSAuthenticator(doc.NewServiceResolver(&doc.Resolver{Store: store.NewMemoryStore()}))
	ctx.connectionManager = grpc.NewGRPCConnectionManager(grpc.NewConfig(listenAddress, peerID), &transport.FixedNodeDIDResolver{NodeDID: did.DID{}}, authenticator, ctx.protocol)

	ctx.protocol.Configure(peerID)
	if err = ctx.connectionManager.Start(); err != nil {
		t.Fatal(err)
	}
	ctx.protocol.Start()
	t.Cleanup(func() {
		ctx.protocol.Stop()
		ctx.connectionManager.Stop()
	})
	return ctx
}

func nameToPort(name string) int {
	return int(crc32.ChecksumIEEE([]byte(name))%9000 + 1000)
}

func nameToAddress(name string) string {
	return fmt.Sprintf("localhost:%d", nameToPort(name))
}
