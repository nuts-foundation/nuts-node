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

package logic

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
)

type broadcastingMissingPayloadCollector struct {
	graph        dag.DAG
	payloadStore dag.PayloadStore
	sender       messageSender
}

// findMissingPayloads returns the payload hashes that are referenced by transactions, but missing in the payload store.
func (c broadcastingMissingPayloadCollector) findMissingPayloads() ([]hash.SHA256Hash, error) {
	var missingPayloadHashes []hash.SHA256Hash
	return missingPayloadHashes, c.payloadStore.ReadMany(context.Background(), func(ctx context.Context, payloadReader dag.PayloadReader) error {
		return c.graph.PayloadHashes(ctx, func(payloadHash hash.SHA256Hash) error {
			present, err := payloadReader.IsPresent(ctx, payloadHash)
			if err != nil {
				return fmt.Errorf("error while checking presence of payload hash (hash=%s): %w", payloadHash, err)
			}
			if !present {
				missingPayloadHashes = append(missingPayloadHashes, payloadHash)
			}
			return nil
		})
	})
}

// queryPeers queries all of our peers for the given payload hashes.
func (c broadcastingMissingPayloadCollector) queryPeers(payloadHashes []hash.SHA256Hash) {
	log.Logger().Debugf("Broadcasting payload query for %d missing payloads", len(payloadHashes))
	for _, payloadHash := range payloadHashes {
		c.sender.broadcastTransactionPayloadQuery(payloadHash)
	}
}

func (c broadcastingMissingPayloadCollector) findAndQueryMissingPayloads() error {
	hashes, err := c.findMissingPayloads()
	if err != nil {
		return err
	}
	c.queryPeers(hashes)
	return nil
}

type missingPayloadCollector interface {
	findMissingPayloads() ([]hash.SHA256Hash, error)
	findAndQueryMissingPayloads() error
}
