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
	"github.com/nuts-foundation/nuts-node/network/protocol/v1/p2p"
	"path"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"

	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/test/io"
)

// TestNetworkIntegration_Pagination tests whether TransactionList messages are paginated when the transactions on the DAG
// exceed Protobuf's max message size.
func TestNetworkIntegration_Pagination(t *testing.T) {
	t.Logf("Running test: %s", t.Name())

	p2p.MaxMessageSizeInBytes = 4 * 1024 // 4kb
	const numberOfTransactions = 19      // 20 transactions equals +/- 12.6kb (which exceeds the set limit of 10kb)

	resetIntegrationTest()
	testDirectory := io.TestDirectory(t)
	key := nutsCrypto.NewTestKey("key")

	node1, err := startNode("pagination_node1", path.Join(testDirectory, "node1"))
	if !assert.NoError(t, err) {
		return
	}
	node2, err := startNode("pagination_node2", path.Join(testDirectory, "node2"))
	if !assert.NoError(t, err) {
		return
	}

	t.Logf("Creating %d transactions...", numberOfTransactions)
	for i := 0; i < numberOfTransactions; i++ {
		_, err := node1.CreateTransaction(payloadType, []byte{1, 2, 3}, key, true, time.Now(), []hash.SHA256Hash{})
		if !assert.NoError(t, err) {
			return
		}
	}

	node2.connectionManager.Connect(nameToAddress("pagination_node1"))
	// Wait until nodes are connected
	if !waitFor(t, func() (bool, error) {
		return len(node1.connectionManager.Peers()) == 1 && len(node2.connectionManager.Peers()) == 1, nil
	}, defaultTimeout, "time-out while waiting for node 1 and 2 to have a peer") {
		return
	}

	waitFor(t, func() (bool, error) {
		mutex.Lock()
		defer mutex.Unlock()
		t.Logf("received %d transactions", len(receivedTransactions["pagination_node2"]))
		return len(receivedTransactions["pagination_node2"]) == numberOfTransactions, nil
	}, 10*time.Second, "node2 didn't receive all transactions")

	defer func() {
		node2.Shutdown()
		node1.Shutdown()
	}()
}
