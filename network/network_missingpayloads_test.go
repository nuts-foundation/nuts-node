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
	"github.com/stretchr/testify/assert"
	"path"
	"testing"
	"time"

	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/test/io"
)

// TestNetworkIntegration_Pagination tests whether TransactionList messages are paginated when the transactions on the DAG
// exceed Protobuf's max message size.
func TestNetworkIntegration_MissingPayloads(t *testing.T) {
	resetIntegrationTest()
	testDirectory := io.TestDirectory(t)
	key := nutsCrypto.NewTestKey("key")

	node1, err := startNode("node1", path.Join(testDirectory, "node1"))
	if !assert.NoError(t, err) {
		return
	}
	node2, err := startNode("node2", path.Join(testDirectory, "node2"), func(config *Config) {
		config.ProtocolV1.CollectMissingPayloadsInterval = 50
	})
	if !assert.NoError(t, err) {
		return
	}

	defer func() {
		node2.Shutdown()
		node1.Shutdown()
	}()

	// Create 2 transactions on node 1; TX0 and TX1. Then write nil as payload for TX1, wiping the payload.
	// Then connect node 2 which should notice the payload of TX1 is missing.
	// Then write the payload to the store on node 1, which should then be queried by node 2
	_, err = node1.CreateTransaction(payloadType, []byte{1, 2, 3}, key, true, time.Now(), nil)
	tx1Payload := []byte{3, 2, 1}
	tx1, err := node1.CreateTransaction(payloadType, tx1Payload, key, true, time.Now(), nil)

	node1.payloadStore.WritePayload(context.Background(), tx1.PayloadHash(), nil)

	node2.connectionManager.Connect(nameToAddress("node1"))
	// Wait until nodes are connected
	if !waitFor(t, func() (bool, error) {
		return len(node1.connectionManager.Peers()) == 1 && len(node2.connectionManager.Peers()) == 1, nil
	}, defaultTimeout, "time-out while waiting for node 1 and 2 to have 2 peers") {
		return
	}

	// Wait for TX0 to arrive
	waitFor(t, func() (bool, error) {
		mutex.Lock()
		defer mutex.Unlock()
		return len(receivedTransactions["node2"]) == 1, nil
	}, 10*time.Second, "node2 didn't receive all transactions")

	// Now write the payload, node 2 should broadcast query node 1 for TX1's payload which it now has
	node1.payloadStore.WritePayload(context.Background(), tx1.PayloadHash(), tx1Payload)
	waitFor(t, func() (bool, error) {
		mutex.Lock()
		defer mutex.Unlock()
		return len(receivedTransactions["node2"]) == 2, nil
	}, 10*time.Second, "node2 didn't receive all transactions")
}
