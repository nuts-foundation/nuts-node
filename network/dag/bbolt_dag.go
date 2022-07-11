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
	"encoding/binary"
	"fmt"
	"math"
	"sort"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
)

// transactionsShelf is the name of the shelf that holds the actual transactions.
const transactionsShelf = "documents"

// headsShelf contains the name of the shelf the holds the heads.
const headsShelf = "heads"

// clockShelf is the name of the shelf that uses the Lamport clock as index to a set of TX refs.
const clockShelf = "clocks"

type dag struct {
	db stoabs.KVStore
}

type headsStatistic struct {
	// SHA256Hash is the last consistency hash.
	heads []hash.SHA256Hash
}

func (h headsStatistic) Result() interface{} {
	return h.heads
}

func (h headsStatistic) Name() string {
	return "heads"
}

func (h headsStatistic) String() string {
	return fmt.Sprintf("%v", h.heads)
}

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
func newDAG(db stoabs.KVStore) *dag {
	return &dag{db: db}
}

func (d *dag) init() error {
	return d.db.Write(func(tx stoabs.WriteTx) error {
		_, _, _, err := getBuckets(tx)
		return err
	})
}

func (d *dag) diagnostics() []core.DiagnosticResult {
	var stats Statistics
	var heads []hash.SHA256Hash
	_ = d.db.Read(func(tx stoabs.ReadTx) error {
		stats = d.statistics(tx)
		heads = d.heads(tx)
		return nil
	})

	result := make([]core.DiagnosticResult, 0)
	result = append(result, headsStatistic{heads: heads})
	result = append(result, numberOfTransactionsStatistic{numberOfTransactions: stats.NumberOfTransactions})
	result = append(result, dataSizeStatistic{sizeInBytes: stats.DataSize})
	return result
}

func (d dag) heads(ctx stoabs.ReadTx) []hash.SHA256Hash {
	result := make([]hash.SHA256Hash, 0)
	reader := ctx.GetShelfReader(headsShelf)
	_ = reader.Iterate(func(key stoabs.Key, _ []byte) error {
		result = append(result, hash.FromSlice(key.Bytes())) // FromSlice() copies
		return nil
	})
	return result
}

func (d *dag) findBetweenLC(tx stoabs.ReadTx, startInclusive uint32, endExclusive uint32) ([]Transaction, error) {
	var result []Transaction

	err := d.visitBetweenLC(tx, startInclusive, endExclusive, func(transaction Transaction) bool {
		result = append(result, transaction)
		return true
	})
	if err != nil {
		// Make sure not to return results in case of error
		return nil, err
	}
	return result, nil
}

func (d *dag) visitBetweenLC(tx stoabs.ReadTx, startInclusive uint32, endExclusive uint32, visitor Visitor) error {
	reader := tx.GetShelfReader(clockShelf)

	// TODO: update to process in batches
	return reader.Range(stoabs.Uint32Key(startInclusive), stoabs.Uint32Key(endExclusive), func(_ stoabs.Key, value []byte) error {
		parsed := parseHashList(value)
		// according to RFC004, lower byte value refs go first
		sort.Slice(parsed, func(i, j int) bool {
			return parsed[i].Compare(parsed[j]) <= 0
		})
		for _, next := range parsed {
			transaction, err := getTransaction(next, tx)
			if err != nil {
				return err
			}
			visitor(transaction)
		}
		return nil
	})
}

func (d *dag) walk(tx stoabs.ReadTx, startLC uint32, visitor Visitor) error {
	return d.visitBetweenLC(tx, startLC, math.MaxUint32, visitor)
}

func (d *dag) isPresent(tx stoabs.ReadTx, ref hash.SHA256Hash) bool {
	reader := tx.GetShelfReader(transactionsShelf)
	return exists(reader, ref)
}

func (d *dag) add(tx stoabs.WriteTx, transactions ...Transaction) error {
	for _, transaction := range transactions {
		if transaction != nil {
			if err := d.addSingle(tx, transaction); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d dag) statistics(tx stoabs.ReadTx) Statistics {
	transactionNum := uint(0)
	dbSize := int64(0)
	reader := tx.GetShelfReader(transactionsShelf)
	shelfStats := reader.Stats()
	transactionNum = shelfStats.NumEntries
	dbSize = int64(shelfStats.ShelfSize)

	return Statistics{
		NumberOfTransactions: transactionNum,
		DataSize:             dbSize,
	}
}

func (d *dag) addSingle(tx stoabs.WriteTx, transaction Transaction) error {
	ref := transaction.Ref()
	refKey := stoabs.NewHashKey(ref)
	transactions, lc, heads, err := getBuckets(tx)
	if err != nil {
		return err
	}
	if exists(transactions, ref) {
		log.Logger().Tracef("Transaction %s already exists, not adding it again.", ref)
		return nil
	}
	if len(transaction.Previous()) == 0 {
		if getRoots(lc) != nil {
			return errRootAlreadyExists
		}
	}
	if err := indexClockValue(tx, transaction); err != nil {
		return fmt.Errorf("unable to calculate LC value for %s: %w", ref, err)
	}
	if err := transactions.Put(refKey, transaction.Data()); err != nil {
		return err
	}
	// Store forward references ([C -> prev A, B] is stored as [A -> C, B -> C])
	for _, prev := range transaction.Previous() {
		// The TX's previous transactions are probably current heads (if there's no other TX referring to it as prev),
		// so it should be unmarked as head.
		if err := heads.Delete(stoabs.NewHashKey(prev)); err != nil {
			return fmt.Errorf("unable to unmark earlier head: %w", err)
		}
	}
	// Transactions are added in order, so the latest TX is always a head
	if err := heads.Put(refKey, []byte{1}); err != nil {
		return fmt.Errorf("unable to mark transaction as head (ref=%s): %w", ref, err)
	}
	return nil
}

func indexClockValue(tx stoabs.WriteTx, transaction Transaction) error {
	lc, err := tx.GetShelfWriter(clockShelf)
	if err != nil {
		return err
	}

	clockKey := stoabs.Uint32Key(transaction.Clock())
	ref := transaction.Ref()
	currentRefs, err := lc.Get(clockKey)
	if err != nil {
		return err
	}
	for _, cRef := range parseHashList(currentRefs) {
		if ref.Equals(cRef) {
			// should only be in the list once
			return nil
		}
	}
	if err := lc.Put(clockKey, appendHashList(currentRefs, ref)); err != nil {
		return err
	}

	log.Logger().Tracef("storing transaction logical clock, txRef: %s, clock: %d", ref.String(), clockKey)

	return nil
}

// returns the highest clock for which a transaction is present in the DAG
func (d dag) getHighestClock() uint32 {
	var clock uint32
	err := d.db.ReadShelf(clockShelf, func(reader stoabs.Reader) error {
		return reader.Iterate(func(key stoabs.Key, _ []byte) error {
			currentClock := bytesToClock(key.Bytes())
			if currentClock > clock {
				clock = currentClock
			}
			return nil
		})
	})
	if err != nil {
		log.Logger().Errorf("failed to read clock shelf: %s", err)
		return 0
	}
	return clock
}

func bytesToClock(clockBytes []byte) uint32 {
	return binary.BigEndian.Uint32(clockBytes)
}

func getBuckets(tx stoabs.WriteTx) (transactions, lc, heads stoabs.Writer, err error) {
	if transactions, err = tx.GetShelfWriter(transactionsShelf); err != nil {
		return
	}
	if lc, err = tx.GetShelfWriter(clockShelf); err != nil {
		return
	}
	if heads, err = tx.GetShelfWriter(headsShelf); err != nil {
		return
	}
	return
}

func getRoots(lcBucket stoabs.Reader) []hash.SHA256Hash {
	roots, err := lcBucket.Get(stoabs.Uint32Key(0))
	if err != nil {
		return nil
	}
	return parseHashList(roots) // no need to copy, calls FromSlice() (which copies)
}

func getTransaction(hash hash.SHA256Hash, tx stoabs.ReadTx) (Transaction, error) {
	transactions := tx.GetShelfReader(transactionsShelf)

	transactionBytes, err := transactions.Get(stoabs.NewHashKey(hash))
	if err != nil || transactionBytes == nil {
		return nil, err
	}
	parsedTx, err := ParseTransaction(transactionBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse transaction %s: %w", hash, err)
	}

	return parsedTx, nil
}

// exists checks whether the transaction with the given ref exists.
func exists(transactions stoabs.Reader, ref hash.SHA256Hash) bool {
	val, _ := transactions.Get(stoabs.NewHashKey(ref))
	return val != nil
}

// parseHashList splits a list of concatenated hashes into separate hashes.
func parseHashList(input []byte) []hash.SHA256Hash {
	if len(input) == 0 {
		return nil
	}
	num := (len(input) - (len(input) % hash.SHA256HashSize)) / hash.SHA256HashSize
	result := make([]hash.SHA256Hash, num)
	for i := 0; i < num; i++ {
		result[i] = hash.FromSlice(input[i*hash.SHA256HashSize : i*hash.SHA256HashSize+hash.SHA256HashSize])
	}
	return result
}

func appendHashList(list []byte, h hash.SHA256Hash) []byte {
	newList := make([]byte, 0, len(list)+hash.SHA256HashSize)
	newList = append(newList, list...)
	newList = append(newList, h.Slice()...)
	return newList
}
