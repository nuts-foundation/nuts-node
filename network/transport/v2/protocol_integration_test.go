/*
 * Nuts node
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
	"fmt"
	"hash/crc32"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const integrationTestTimeout = 10 * time.Second

// TestProtocolV2_Pagination tests whether TransactionList messages are paginated when the transactions on the DAG
// about 15 transactions fit into a message with max size 4k
func TestProtocolV2_Pagination(t *testing.T) {
	prevMaxSize := grpc.MaxMessageSizeInBytes
	grpc.MaxMessageSizeInBytes = 4 * 1024
	const numberOfTransactions = 30
	t.Cleanup(func() {
		grpc.MaxMessageSizeInBytes = prevMaxSize
	})

	node1 := startNode(t, "v2_pagination_node1")
	node2 := startNode(t, "v2_pagination_node2")

	t.Logf("Creating %d transactions...", numberOfTransactions)
	rootTX, _, _ := dag.CreateTestTransaction(1)
	err := node1.state.Add(context.Background(), rootTX, []byte{0, 0, 0, 1})
	require.NoError(t, err)
	prev := rootTX
	transactions := make([]dag.Transaction, numberOfTransactions)
	transactions[0] = rootTX
	for i := 0; i < numberOfTransactions-1; i++ { // minus 1 to subtract root TX
		tx, _, _ := dag.CreateTestTransaction(uint32(i+2), prev)
		err := node1.state.Add(context.Background(), tx, []byte{0, 0, 0, byte(i + 2)})
		require.NoError(t, err)
		prev = tx
		transactions[i+1] = tx
	}

	node2.connectionManager.Connect(nameToAddress("v2_pagination_node1"), did.DID{}, nil)
	// Wait until nodes are connected
	if !test.WaitFor(t, func() (bool, error) {
		return len(node1.connectionManager.Peers()) == 1 && len(node2.connectionManager.Peers()) == 1, nil
	}, integrationTestTimeout, "time-out while waiting for node 1 and 2 to have a peer") {
		return
	}

	// manually request
	hashes := make([]hash.SHA256Hash, numberOfTransactions)
	for i, tx := range transactions {
		hashes[i] = tx.Ref()
	}
	conn := node2.protocol.connectionList.Get(grpc.ByPeerID("v2_pagination_node1"))
	err = node2.protocol.sendTransactionListQuery(conn, hashes)
	assert.NoError(t, err)

	test.WaitFor(t, func() (bool, error) {
		txs := node2.countTXs()
		t.Logf("received %d transactions", txs)
		return txs == numberOfTransactions, nil
	}, integrationTestTimeout, "node2 didn't receive all transactions")
	time.Sleep(100 * time.Millisecond) // small timeout for TXs to propagate within the node

	// Confirm that both nodes have the same non-empty XOR
	assert.NotEqual(t, node1.state.Diagnostics()[2].Result(), hash.EmptyHash())
	assert.Equal(t, node1.state.Diagnostics()[2].Result(), node2.state.Diagnostics()[2].Result())
}

type integrationTestContext struct {
	protocol          *protocol
	receivedTXs       []dag.Transaction
	mux               *sync.Mutex
	state             dag.State
	connectionManager transport.ConnectionManager
}

func (i *integrationTestContext) countTXs() int {
	i.mux.Lock()
	defer i.mux.Unlock()
	return len(i.receivedTXs)
}
func startNode(t *testing.T, name string, configurers ...func(config *Config)) *integrationTestContext {
	var vdrStore didstore.Store
	var keyStore nutsCrypto.KeyStore

	log.Logger().Infof("Starting node: %s", name)
	logrus.SetLevel(logrus.DebugLevel)

	testDirectory := path.Join(io.TestDirectory(t), name)

	ctx := &integrationTestContext{
		mux: &sync.Mutex{},
	}

	storageClient := storage.NewTestStorageEngine(testDirectory)
	bboltStore, err := storageClient.GetProvider("network").GetKVStore("data", storage.PersistentStorageClass)
	if err != nil {
		t.Fatal(err)
	}

	ctx.state, _ = dag.NewState(bboltStore)
	ctx.state.Notifier(t.Name(), func(event dag.Event) (bool, error) {
		log.Logger().Infof("Transaction %s arrived at %s", string(event.Payload), name)
		ctx.mux.Lock()
		defer ctx.mux.Unlock()
		ctx.receivedTXs = append(ctx.receivedTXs, event.Transaction)
		return true, nil
	}, dag.WithSelectionFilter(func(event dag.Event) bool {
		return event.Type == dag.PayloadEventType
	}))
	err = ctx.state.Start()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		GossipInterval: 500,
		Datadir:        testDirectory,
	}
	for _, c := range configurers {
		c(cfg)
	}
	peerID := transport.PeerID(name)
	listenAddress := fmt.Sprintf("localhost:%d", nameToPort(name))
	ctx.protocol = New(*cfg, did.DID{}, ctx.state, didservice.Resolver{Store: vdrStore}, keyStore, nil, bboltStore).(*protocol)

	authenticator := grpc.NewTLSAuthenticator(didservice.NewServiceResolver(&didservice.Resolver{Store: didstore.NewTestStore(t)}))
	connectionsStore, _ := storageClient.GetProvider("network").GetKVStore("connections", storage.VolatileStorageClass)
	grpcCfg, err := grpc.NewConfig(listenAddress, peerID)
	require.NoError(t, err)
	ctx.connectionManager, err = grpc.NewGRPCConnectionManager(grpcCfg, connectionsStore, did.DID{}, authenticator, ctx.protocol)
	require.NoError(t, err)

	ctx.protocol.Configure(peerID)
	if err := ctx.connectionManager.Start(); err != nil {
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
