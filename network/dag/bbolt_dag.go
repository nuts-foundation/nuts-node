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
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
)

// transactionsBucket is the name of the Bolt bucket that holds the actual transactions as JSON.
const transactionsBucket = "documents"

// headsBucket contains the name of the bucket the holds the heads.
const headsBucket = "heads"

// clockIndexBucket is the name of the bucket that holds the mappings from TX ref to lamport clock value. This is required for V1 transactions that are missing the lc header.
const clockIndexBucket = "clockIndex"

// clockBucket is the name of the bucket that uses the Lamport clock as index to a set of TX refs.
const clockBucket = "clocks"

type bboltDAG struct {
	db stoabs.KVStore
}

type headsStatistic struct {
	// SHA256Hash is the last consistency Hash.
	heads []hash.SHA256Hash
}

func (d headsStatistic) Result() interface{} {
	return d.heads
}

func (d headsStatistic) Name() string {
	return "heads"
}

func (d headsStatistic) String() string {
	return fmt.Sprintf("%v", d.heads)
}

type numberOfTransactionsStatistic struct {
	numberOfTransactions uint
}

func (d numberOfTransactionsStatistic) Result() interface{} {
	return d.numberOfTransactions
}

func (d numberOfTransactionsStatistic) Name() string {
	return "transaction_count"
}

func (d numberOfTransactionsStatistic) String() string {
	return fmt.Sprintf("%d", d.numberOfTransactions)
}

type dataSizeStatistic struct {
	sizeInBytes int64
}

func (d dataSizeStatistic) Result() interface{} {
	return d.sizeInBytes
}

func (d dataSizeStatistic) Name() string {
	return "stored_database_size_bytes"
}

func (d dataSizeStatistic) String() string {
	return fmt.Sprintf("%d", d.sizeInBytes)
}

// newBBoltDAG creates the DAG using the given database.
func newBBoltDAG(db stoabs.KVStore) *bboltDAG {
	return &bboltDAG{db: db}
}

func (dag *bboltDAG) init() error {
	return dag.db.Write(func(tx stoabs.WriteTx) error {
		_, _, _, _, err := getBuckets(tx)
		return err
	})
}

func (dag *bboltDAG) diagnostics() []core.DiagnosticResult {
	result := make([]core.DiagnosticResult, 0)
	ctx := context.Background()
	stats := dag.statistics(ctx)
	result = append(result, headsStatistic{heads: dag.heads()})
	result = append(result, numberOfTransactionsStatistic{numberOfTransactions: stats.NumberOfTransactions})
	result = append(result, dataSizeStatistic{sizeInBytes: stats.DataSize})
	return result
}

func (dag bboltDAG) heads() []hash.SHA256Hash {
	result := make([]hash.SHA256Hash, 0)
	dag.db.Read(func(tx stoabs.ReadTx) error {
		heads, _ := tx.GetShelfReader(headsBucket)
		if heads == nil {
			return nil
		}

		return heads.Iterate(func(key stoabs.Key, value []byte) error {
			result = append(result, hash.FromSlice(key.Bytes())) // FromSlice() copies
			return nil
		})
	})
	return result
}

func (dag *bboltDAG) findBetweenLC(readTx stoabs.ReadTx, startInclusive uint32, endExclusive uint32) ([]Transaction, error) {
	var result []Transaction

	reader, err := readTx.GetShelfReader(clockBucket)
	if err != nil {
		return nil, err
	}
	err = reader.Range(stoabs.Uint32Key(startInclusive), stoabs.Uint32Key(endExclusive), func(key stoabs.Key, value []byte) error {
		parsed := parseHashList(value)
		// according to RFC004, lower byte value refs go first
		sort.Slice(parsed, func(i, j int) bool {
			return parsed[i].Compare(parsed[j]) <= 0
		})
		for _, next := range parsed {
			transaction, err := getTransaction(next, readTx)
			if err != nil {
				return err
			}
			result = append(result, transaction)
		}
		return nil
	})

	if err != nil {
		// Make sure not to return results in case of error
		return nil, err
	}
	return result, nil
}

func (dag bboltDAG) isPresent(tx stoabs.ReadTx, ref hash.SHA256Hash) bool {
	if reader, _ := tx.GetShelfReader(transactionsBucket); reader != nil {
		data, _ := reader.Get(stoabs.BytesKey(ref.Slice()))
		return data != nil
	}
	return false
}

func (dag *bboltDAG) add(tx stoabs.WriteTx, transactions ...Transaction) error {
	for _, transaction := range transactions {
		if transaction != nil {
			if err := dag.addSingle(tx, transaction); err != nil {
				return err
			}
		}
	}
	return nil
}

func (dag bboltDAG) statistics(ctx context.Context) Statistics {
	transactionNum := uint(0)
	dbSize := int64(0)

	_ = dag.db.Read(func(tx stoabs.ReadTx) error {
		if bucket, _ := tx.GetShelfReader(transactionsBucket); bucket != nil {
			transactionNum = bucket.Stats().NumEntries
		}
		return nil
	})

	return Statistics{
		NumberOfTransactions: transactionNum,
		DataSize:             dbSize,
	}
}

func (dag *bboltDAG) addSingle(tx stoabs.WriteTx, transaction Transaction) error {
	ref := transaction.Ref()
	refSlice := ref.Slice()
	transactions, lc, _, heads, err := getBuckets(tx)
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
	if err := transactions.Put(stoabs.BytesKey(refSlice), transaction.Data()); err != nil {
		return err
	}
	// Store forward references ([C -> prev A, B] is stored as [A -> C, B -> C])
	for _, prev := range transaction.Previous() {
		// The TX's previous transactions are probably current heads (if there's no other TX referring to it as prev),
		// so it should be unmarked as head.
		if err := heads.Delete(stoabs.BytesKey(prev.Slice())); err != nil {
			return fmt.Errorf("unable to unmark earlier head: %w", err)
		}
	}
	// Transactions are added in order, so the latest TX is always a head
	if err := heads.Put(stoabs.BytesKey(refSlice), []byte{1}); err != nil {
		return fmt.Errorf("unable to mark transaction as head (ref=%s): %w", ref, err)
	}

	return nil
}

func indexClockValue(tx stoabs.WriteTx, transaction Transaction) error {
	lc, err := tx.GetShelfWriter(clockBucket)
	if err != nil {
		return err
	}
	lcIndex, err := tx.GetShelfWriter(clockIndexBucket)
	if err != nil {
		return err
	}

	clock := transaction.Clock()
	ref := transaction.Ref()

	val, _ := lcIndex.Get(stoabs.BytesKey(ref.Slice()))
	if val != nil {
		// already added
		return nil
	}

	clockBytes := clockToBytes(clock)
	currentRefs, _ := lc.Get(stoabs.BytesKey(clockBytes))

	if err := lc.Put(stoabs.BytesKey(clockBytes), appendHashList(currentRefs, ref)); err != nil {
		return err
	}
	if err := lcIndex.Put(stoabs.BytesKey(ref.Slice()), clockBytes); err != nil {
		return err
	}

	log.Logger().Tracef("storing transaction logical clock, txRef: %s, clock: %d", ref.String(), clock)

	return nil
}

// returns the highest clock for which a transaction is present in the DAG
func (dag bboltDAG) getHighestClock() uint32 {
	var clock uint32
	_ = dag.db.ReadShelf(clockBucket, func(tx stoabs.Reader) error {
		return tx.Iterate(func(key stoabs.Key, value []byte) error {
			lastClock := bytesToClock(key.Bytes())
			if lastClock > clock {
				clock = lastClock
			}
			return nil
		})
	})

	return clock
}

func bytesToClock(clockBytes []byte) uint32 {
	return binary.BigEndian.Uint32(clockBytes)
}

func clockToBytes(clock uint32) []byte {
	clockBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(clockBytes, clock)
	return clockBytes[:]
}

func getBuckets(tx stoabs.WriteTx) (transactions, lc, lcIndex, heads stoabs.Writer, err error) {
	if transactions, err = tx.GetShelfWriter(transactionsBucket); err != nil {
		return
	}
	if lc, err = tx.GetShelfWriter(clockBucket); err != nil {
		return
	}
	if lcIndex, err = tx.GetShelfWriter(clockIndexBucket); err != nil {
		return
	}
	if heads, err = tx.GetShelfWriter(headsBucket); err != nil {
		return
	}
	return
}

func getRoots(lcBucket stoabs.Writer) []hash.SHA256Hash {
	list, _ := lcBucket.Get(stoabs.BytesKey(clockToBytes(0)))
	return parseHashList(list) // no need to copy, calls FromSlice() (which copies)
}

func getTransaction(hash hash.SHA256Hash, tx stoabs.ReadTx) (Transaction, error) {
	transactions, _ := tx.GetShelfReader(transactionsBucket)
	if transactions == nil {
		return nil, nil
	}

	transactionBytes, _ := transactions.Get(stoabs.BytesKey(hash.Slice()))
	if transactionBytes == nil {
		return nil, nil
	}
	parsedTx, err := ParseTransaction(transactionBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse transaction %s: %w", hash, err)
	}

	return parsedTx, nil
}

// exists checks whether the transaction with the given ref exists.
func exists(transactions stoabs.Writer, ref hash.SHA256Hash) bool {
	v, _ := transactions.Get(stoabs.BytesKey(ref.Slice()))
	return v != nil
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
