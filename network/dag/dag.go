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

package dag

import (
	"context"
	"fmt"
	"sort"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
)

type dag struct {
	// Collect each transaction/JWS by its own data hash.
	jWSPerHash map[hash.SHA256Hash][]byte
	jWSByteN   int64 // total size of all JWS entries together

	// Group each transaction/JWS hash in its respective lamport clock tick
	// sorted as per Nuts RFC004.
	hashesPerClock [][]*hash.SHA256Hash
}

// HighestLamportClock returns the latest value present in the graph.
// with -1 for an empty graph, and 0 for only a root node present.
func (d *dag) highestLamportClock() int { return len(d.hashesPerClock) - 1 }

// HeadTxHash returns the latest transaction hash present in the graph.
func (d *dag) headTxHash() hash.SHA256Hash {
	if len(d.hashesPerClock) == 0 {
		return hash.SHA256Hash{}
	}
	latest := d.hashesPerClock[len(d.hashesPerClock)-1]
	return *latest[len(latest)-1]
}

// TxCount returns to total amount of transactions present in the graph.
func (d *dag) txCount() int { return len(d.jWSPerHash) }

type numberOfTransactionsStatistic struct {
	numberOfTransactions uint
}

func (n numberOfTransactionsStatistic) Result() interface{} {
	return n.numberOfTransactions
}

func (n numberOfTransactionsStatistic) Name() string {
	return "transaction_count"
}

func (n numberOfTransactionsStatistic) String() string {
	return fmt.Sprintf("%d", n.numberOfTransactions)
}

type dataSizeStatistic struct {
	sizeInBytes int64
}

func (s dataSizeStatistic) Result() interface{} {
	return s.sizeInBytes
}

func (s dataSizeStatistic) Name() string {
	return "stored_database_size_bytes"
}

func (s dataSizeStatistic) String() string {
	return fmt.Sprintf("%d", s.sizeInBytes)
}

// newDAG creates a DAG backed by the given database.
func newDAG() *dag {
	return &dag{
		jWSPerHash: make(map[hash.SHA256Hash][]byte),
	}
}

func (d *dag) diagnostics(ctx context.Context) []core.DiagnosticResult {
	return []core.DiagnosticResult{
		numberOfTransactionsStatistic{numberOfTransactions: uint(len(d.jWSPerHash))},
		dataSizeStatistic{sizeInBytes: d.jWSByteN},
	}
}

func (d *dag) findBetweenLC(startInclusive, endExclusive uint32) []Transaction {
	var txs []Transaction
	d.visitBetweenLC(startInclusive, endExclusive, func(tx Transaction) bool {
		txs = append(txs, tx)
		return true
	})
	return txs
}

func (d *dag) visitBetweenLC(startInclusive uint32, endExclusive uint32, callback Visitor) {
	if n := len(d.hashesPerClock); n < int(uint(endExclusive)) {
		endExclusive = uint32(n)
	}
	if endExclusive <= startInclusive {
		return
	}

	for _, hashes := range d.hashesPerClock[startInclusive:endExclusive] {
		for _, hash := range hashes {
			bytes, ok := d.jWSPerHash[*hash]
			if !ok {
				log.Logger().WithField(core.LogFieldTransactionRef, hash).Error("DAG: JWS entry went missing")
				continue
			}
			p, err := ParseTransaction(bytes)
			if err != nil {
				log.Logger().WithField(core.LogFieldTransactionRef, hash).WithError(err).Error("DAG: JWS entry corrupted")
				continue
			}
			if !callback(p) {
				return
			}
		}
	}
}

func (d *dag) containsTxHash(h hash.SHA256Hash) bool {
	_, ok := d.jWSPerHash[h]
	return ok
}

func (d *dag) addTx(tx Transaction) error {
	h := tx.Ref()

	if _, ok := d.jWSPerHash[h]; ok {
		log.Logger().
			WithField(core.LogFieldTransactionRef, h).
			Trace("Transaction already exists, not adding it again.")
		return nil
	}

	if len(tx.Previous()) == 0 && len(d.hashesPerClock) != 0 {
		return errRootAlreadyExists
	}

	JWS := tx.Data()
	d.jWSPerHash[h] = JWS
	d.jWSByteN += int64(len(JWS))

	clock := tx.Clock()
	switch {
	case int(clock) == len(d.hashesPerClock):
		d.hashesPerClock = append(d.hashesPerClock, []*hash.SHA256Hash{&h})

	case int(clock) < len(d.hashesPerClock):
		d.hashesPerClock[clock] = append(d.hashesPerClock[clock], &h)
		// Sort hashes on byte value per Nuts RFC004.
		sort.Slice(d.hashesPerClock[clock], func(i, j int) bool {
			return d.hashesPerClock[clock][i].Compare(*d.hashesPerClock[clock][j]) < 0
		})

	default:
		// should not happen ™️ after validation
		return fmt.Errorf("dag: entry with lamport clock %d denied, last is %d", clock, d.highestLamportClock())
	}

	return nil
}

// TxByHash does a lookup with ErrTransactionNotFound for absense.
func (d *dag) txByHash(hash hash.SHA256Hash) (Transaction, error) {
	bytes, ok := d.jWSPerHash[hash]
	if !ok {
		return nil, ErrTransactionNotFound
	}
	p, err := ParseTransaction(bytes)
	if err != nil {
		return nil, fmt.Errorf("transaction %s corrupted: %w", hash, err)
	}
	return p, nil
}
