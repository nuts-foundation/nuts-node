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
	"github.com/nuts-foundation/nuts-node/storage"
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
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/store"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const integrationTestTimeout = 10 * time.Second
const integrationTestPayloadType = "application/did+json"

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
	if !assert.NoError(t, err) {
		return
	}
	prev := rootTX
	transactions := make([]dag.Transaction, numberOfTransactions)
	transactions[0] = rootTX
	for i := 0; i < numberOfTransactions-1; i++ { // minus 1 to subtract root TX
		tx, _, _ := dag.CreateTestTransaction(uint32(i+2), prev)
		err := node1.state.Add(context.Background(), tx, []byte{0, 0, 0, byte(i + 2)})
		if !assert.NoError(t, err) {
			return
		}
		prev = tx
		transactions[i+1] = tx
	}

	node2.connectionManager.Connect(nameToAddress("v2_pagination_node1"))
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
	err = node2.protocol.sendTransactionListQuery("v2_pagination_node1", hashes)
	assert.NoError(t, err)

	test.WaitFor(t, func() (bool, error) {
		txs := node2.countTXs()
		t.Logf("received %d transactions", txs)
		return txs == numberOfTransactions, nil
	}, integrationTestTimeout, "node2 didn't receive all transactions")

	// Confirm that both nodes have the same non-empty XOR
	assert.NotEqual(t, node1.state.Diagnostics()[3].Result(), hash.EmptyHash())
	assert.Equal(t, node1.state.Diagnostics()[3].Result(), node2.state.Diagnostics()[3].Result())
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
	var vdrStore vdr.Store
	var keyStore nutsCrypto.KeyStore

	log.Logger().Infof("Starting node: %s", name)
	logrus.SetLevel(logrus.DebugLevel)

	testDirectory := path.Join(io.TestDirectory(t), name)

	ctx := &integrationTestContext{
		mux: &sync.Mutex{},
	}

	ctx.state, _ = dag.NewState(testDirectory)
	ctx.state.Subscribe(dag.TransactionPayloadAddedEvent, integrationTestPayloadType, func(tx dag.Transaction, payload []byte) error {
		log.Logger().Infof("transaction %s arrived at %s", string(payload), name)
		ctx.mux.Lock()
		defer ctx.mux.Unlock()
		ctx.receivedTXs = append(ctx.receivedTXs, tx)
		return nil
	})
	ctx.state.Start()

	cfg := &Config{
		GossipInterval:      500,
		Datadir:             testDirectory,
	}
	for _, c := range configurers {
		c(cfg)
	}
	peerID := transport.PeerID(name)
	listenAddress := fmt.Sprintf("localhost:%d", nameToPort(name))
	ctx.protocol = New(*cfg, transport.FixedNodeDIDResolver{}, ctx.state, doc.Resolver{Store: vdrStore}, keyStore, nil).(*protocol)

	authenticator := grpc.NewTLSAuthenticator(doc.NewServiceResolver(&doc.Resolver{Store: store.NewMemoryStore()}))
	connectionsStore, _ := storage.CreateTestBBoltStore(path.Join(testDirectory, "connections.db"))
	ctx.connectionManager = grpc.NewGRPCConnectionManager(grpc.NewConfig(listenAddress, peerID), connectionsStore, &transport.FixedNodeDIDResolver{NodeDID: did.DID{}}, authenticator, ctx.protocol)

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
