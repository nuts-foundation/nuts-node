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
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
	"go.etcd.io/bbolt"
)

// transactionsBucket is the name of the Bolt bucket that holds the actual transactions as JSON.
const transactionsBucket = "documents"

// payloadIndexBucket is the name of the Bolt bucket that holds the reverse reference from payload hash back to transactions.
// The value ([]byte) should be split in chunks of HashSize where each entry is a transaction reference that refers to
// the payload.
const payloadIndexBucket = "payloadIndex"

// nextsBucket is the name of the Bolt bucket that holds the forward transaction references (a.k.a. "nexts") as transaction
// refs. The value ([]byte) should be split in chunks of HashSize where each entry is a forward reference (next).
const nextsBucket = "nexts"

// rootsTransactionKey is the name of the bucket entry that holds the refs of the root transactions.
const rootsTransactionKey = "roots"

// headsBucket contains the name of the bucket the holds the heads.
const headsBucket = "heads"

// clockIndexBucket is the name of the bucket that holds the mappings from TX ref to lamport clock value. This is required for V1 transactions that are missing the lc header.
const clockIndexBucket = "clockIndex"

// clockBucket is the name of the bucket that uses the Lamport clock as index to a set of TX refs.
const clockBucket = "clocks"

type bboltDAG struct {
	db          *bbolt.DB
	observers   []Observer
	txVerifiers []Verifier
}

func (dag *bboltDAG) Verify(ctx context.Context) error {
	transactions, err := dag.FindBetween(ctx, MinTime(), MaxTime())
	if err != nil {
		return err
	}
	for _, tx := range transactions {
		if err := dag.verifyTX(ctx, tx); err != nil {
			return err
		}
	}
	return nil
}

type headsStatistic struct {
	// SHA256Hash is the last consistency hash.
	heads []hash.SHA256Hash
}

func (d headsStatistic) Name() string {
	return "[DAG] Heads"
}

func (d headsStatistic) String() string {
	return fmt.Sprintf("%v", d.heads)
}

type numberOfTransactionsStatistic struct {
	numberOfTransactions int
}

func (d numberOfTransactionsStatistic) Name() string {
	return "[DAG] Number of transactions"
}

func (d numberOfTransactionsStatistic) String() string {
	return fmt.Sprintf("%d", d.numberOfTransactions)
}

type dataSizeStatistic struct {
	sizeInBytes int
}

func (d dataSizeStatistic) Name() string {
	return "[DAG] Stored database size (bytes)"
}

func (d dataSizeStatistic) String() string {
	return fmt.Sprintf("%d", d.sizeInBytes)
}

// NewBBoltDAG creates a etcd/bbolt backed DAG using the given database.
func NewBBoltDAG(db *bbolt.DB, txVerifiers ...Verifier) DAG {
	return &bboltDAG{db: db, txVerifiers: txVerifiers}
}

func (dag *bboltDAG) Migrate() error {
	// We'll take the root and then use nexts to add the Transactions in the right order
	err := dag.db.Update(func(tx *bbolt.Tx) error {
		if tx.Bucket([]byte(nextsBucket)) == nil {
			// already migrated
			return nil
		}

		log.Logger().Info("DAG migrations: adding logical clock values to transactions")

		// get root
		transactions := tx.Bucket([]byte(transactionsBucket))
		roots := parseHashList(transactions.Get([]byte(rootsTransactionKey)))

		for nexts, err := migrateAddClocks(tx, []hash.SHA256Hash{roots[0]}); len(nexts) != 0; nexts, err = migrateAddClocks(tx, nexts) {
			if err != nil {
				return err
			}
		}

		// remove nexts
		if err := tx.DeleteBucket([]byte(nextsBucket)); err != nil {
			return err
		}
		// remove root
		return transactions.Delete([]byte(rootsTransactionKey))
	})
	if err != nil {
		return err
	}

	log.Logger().Info("DAG migrations: done")
	return nil
}

func migrateAddClocks(tx *bbolt.Tx, refs []hash.SHA256Hash) ([]hash.SHA256Hash, error) {
	nextBucket := tx.Bucket([]byte(nextsBucket))
	txBucket := tx.Bucket([]byte(transactionsBucket))
	var nexts []hash.SHA256Hash
	var retry []hash.SHA256Hash

	for _, ref := range refs {
		transaction, err := ParseTransaction(txBucket.Get(ref.Slice()))
		if err != nil {
			return nexts, err
		}
		// indexClockValue uses the prevs to guarantee ordering
		if err := indexClockValue(tx, transaction); err != nil {
			// we hit a branch and have processed a TX to soon, retry later
			retry = append(retry, ref)
		}

		// find next TXs from nexts bucket
		nexts = append(nexts, parseHashList(nextBucket.Get(ref.Slice()))...)
	}

	// nexts have a lot of doubles
	return unique(append(nexts, retry...)), nil
}

func unique(list []hash.SHA256Hash) []hash.SHA256Hash {
	set := map[hash.SHA256Hash]bool{}

	for _, v := range list {
		set[v] = true
	}

	result := make([]hash.SHA256Hash, 0)
	for k := range set {
		result = append(result, k)
	}

	return result
}

func (dag *bboltDAG) RegisterObserver(observer Observer) {
	dag.observers = append(dag.observers, observer)
}

func (dag *bboltDAG) Diagnostics() []core.DiagnosticResult {
	result := make([]core.DiagnosticResult, 0)
	ctx := context.Background()
	stats := dag.Statistics(ctx)
	result = append(result, headsStatistic{heads: dag.Heads(ctx)})
	result = append(result, numberOfTransactionsStatistic{numberOfTransactions: stats.NumberOfTransactions})
	result = append(result, dataSizeStatistic{sizeInBytes: stats.DataSize})
	return result
}

func (dag bboltDAG) Get(ctx context.Context, ref hash.SHA256Hash) (Transaction, error) {
	var result Transaction
	var err error
	err = bboltTXView(ctx, dag.db, func(ctx context.Context, tx *bbolt.Tx) error {
		if transactions := tx.Bucket([]byte(transactionsBucket)); transactions != nil {
			result, err = getTransaction(ref, tx)
			return err
		}
		return nil
	})
	return result, err
}

func (dag bboltDAG) GetByPayloadHash(ctx context.Context, payloadHash hash.SHA256Hash) ([]Transaction, error) {
	result := make([]Transaction, 0)
	err := bboltTXView(ctx, dag.db, func(ctx context.Context, tx *bbolt.Tx) error {
		transactions := tx.Bucket([]byte(transactionsBucket))
		payloadIndex := tx.Bucket([]byte(payloadIndexBucket))
		if transactions == nil || payloadIndex == nil {
			return nil
		}
		transactionHashes := parseHashList(payloadIndex.Get(payloadHash.Slice()))
		for _, transactionHash := range transactionHashes {
			transaction, err := getTransaction(transactionHash, tx)
			if err != nil {
				return err
			}
			result = append(result, transaction)
		}
		return nil
	})
	return result, err
}

func (dag *bboltDAG) PayloadHashes(ctx context.Context, visitor func(payloadHash hash.SHA256Hash) error) error {
	return bboltTXView(ctx, dag.db, func(ctx context.Context, tx *bbolt.Tx) error {
		payloadIndex := tx.Bucket([]byte(payloadIndexBucket))
		if payloadIndex == nil {
			return nil
		}
		cursor := payloadIndex.Cursor()
		for ref, _ := cursor.First(); ref != nil; ref, _ = cursor.Next() {
			err := visitor(hash.FromSlice(ref)) // FromSlice() copies
			if err != nil {
				return fmt.Errorf("visitor returned error: %w", err)
			}
		}
		return nil
	})
}

func (dag bboltDAG) Heads(ctx context.Context) []hash.SHA256Hash {
	result := make([]hash.SHA256Hash, 0)
	_ = bboltTXView(ctx, dag.db, func(ctx context.Context, tx *bbolt.Tx) error {
		heads := tx.Bucket([]byte(headsBucket))
		if heads == nil {
			return nil
		}
		cursor := heads.Cursor()
		for ref, _ := cursor.First(); ref != nil; ref, _ = cursor.Next() {
			result = append(result, hash.FromSlice(ref)) // FromSlice() copies
		}
		return nil
	})
	return result
}

func (dag *bboltDAG) FindBetween(ctx context.Context, startInclusive time.Time, endExclusive time.Time) ([]Transaction, error) {
	var result []Transaction
	err := dag.Walk(ctx, func(ctx context.Context, transaction Transaction) bool {
		if !transaction.SigningTime().Before(startInclusive) && transaction.SigningTime().Before(endExclusive) {
			result = append(result, transaction)
		}
		return true
	}, hash.EmptyHash())
	return result, err
}

func (dag bboltDAG) IsPresent(ctx context.Context, ref hash.SHA256Hash) (bool, error) {
	var result bool
	err := bboltTXView(ctx, dag.db, func(ctx context.Context, tx *bbolt.Tx) error {
		if payloads := tx.Bucket([]byte(transactionsBucket)); payloads != nil {
			data := payloads.Get(ref.Slice())
			result = data != nil
		}
		return nil
	})
	return result, err
}

func (dag *bboltDAG) Add(ctx context.Context, transactions ...Transaction) error {
	for _, transaction := range transactions {
		if transaction != nil {
			if err := dag.add(ctx, transaction); err != nil {
				return err
			}
		}
	}
	return nil
}

func (dag bboltDAG) Walk(ctx context.Context, visitor Visitor, startAt hash.SHA256Hash) error {
	return bboltTXView(ctx, dag.db, func(ctx context.Context, tx *bbolt.Tx) error {
		transactions := tx.Bucket([]byte(transactionsBucket))
		clocksBucket := tx.Bucket([]byte(clockBucket))
		if transactions == nil {
			// DAG is empty
			return nil
		}

		// we find the clock value of the TX ref
		// an empty hash means start at root
		clockValue, err := getClock(tx, startAt)
		if !hash.EmptyHash().Equals(startAt) && err != nil {
			return err
		}

		// initiate a cursor and start from the given lcValue
		cursor := clocksBucket.Cursor()

	outer:
		for _, list := cursor.Seek(clockToBytes(clockValue)); list != nil; _, list = cursor.Next() {

			parsed := parseHashList(list)
			// according to RFC004, lower byte value refs go first
			sort.Slice(parsed, func(i, j int) bool {
				return parsed[i].Compare(parsed[j]) <= 0
			})
			for _, next := range parsed {
				transaction, err := getTransaction(next, tx)
				if err != nil {
					return err
				}
				if !visitor(ctx, transaction) {
					break outer
				}
			}
		}

		return nil
	})
}

func (dag bboltDAG) Statistics(ctx context.Context) Statistics {
	transactionNum := 0
	_ = bboltTXView(ctx, dag.db, func(ctx context.Context, tx *bbolt.Tx) error {
		if bucket := tx.Bucket([]byte(transactionsBucket)); bucket != nil {
			transactionNum = bucket.Stats().KeyN
		}
		return nil
	})
	return Statistics{
		NumberOfTransactions: transactionNum,
		DataSize:             dag.db.Stats().TxStats.PageAlloc,
	}
}

func (dag *bboltDAG) verifyTX(ctx context.Context, tx Transaction) error {
	for _, verifier := range dag.txVerifiers {
		if err := verifier(ctx, tx, dag); err != nil {
			return fmt.Errorf("transaction verification failed (tx=%s): %w", tx.Ref(), err)
		}
	}
	return nil
}

func (dag *bboltDAG) add(ctx context.Context, transaction Transaction) error {
	if err := dag.verifyTX(ctx, transaction); err != nil {
		return err
	}
	ref := transaction.Ref()
	refSlice := ref.Slice()
	err := bboltTXUpdate(ctx, dag.db, func(ctx context.Context, tx *bbolt.Tx) error {
		transactions, lc, _, payloadIndex, heads, err := getBuckets(tx)
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
		if err := transactions.Put(refSlice, transaction.Data()); err != nil {
			return err
		}
		// Store forward references ([C -> prev A, B] is stored as [A -> C, B -> C])
		for _, prev := range transaction.Previous() {
			// The TX's previous transactions are probably current heads (if there's no other TX referring to it as prev),
			// so it should be unmarked as head.
			if err := heads.Delete(prev.Slice()); err != nil {
				return fmt.Errorf("unable to unmark earlier head: %w", err)
			}
		}
		// Transactions are added in order, so the latest TX is always a head
		if err := heads.Put(refSlice, []byte{1}); err != nil {
			return fmt.Errorf("unable to mark transaction as head (ref=%s): %w", ref, err)
		}
		// Store reverse reference from payload hash to transaction
		newPayloadIndexValue := appendHashList(copyBBoltValue(payloadIndex, transaction.PayloadHash().Slice()), ref)
		if err = payloadIndex.Put(transaction.PayloadHash().Slice(), newPayloadIndexValue); err != nil {
			return fmt.Errorf("unable to update payload index for transaction %s: %w", ref, err)
		}
		return nil
	})
	if err == nil {
		notifyObservers(ctx, dag.observers, transaction)
	}
	return err
}

func indexClockValue(tx *bbolt.Tx, transaction Transaction) error {
	lc, err := tx.CreateBucketIfNotExists([]byte(clockBucket))
	if err != nil {
		return err
	}
	lcIndex, err := tx.CreateBucketIfNotExists([]byte(clockIndexBucket))
	if err != nil {
		return err
	}

	clock := uint32(0)
	ref := transaction.Ref()

	if lcIndex.Get(ref.Slice()) != nil {
		// already added
		return nil
	}

	for _, prev := range transaction.Previous() {
		lClockBytes := lcIndex.Get(prev.Slice())
		if lClockBytes == nil {
			return fmt.Errorf("clock value not found for TX ref: %s", prev.String())
		}
		lClock := bytesToClock(lClockBytes)
		if lClock >= clock {
			clock = lClock + 1
		}
	}

	clockBytes := clockToBytes(clock)
	currentRefs := lc.Get(clockBytes)

	if err := lc.Put(clockBytes, appendHashList(currentRefs, ref)); err != nil {
		return err
	}
	if err := lcIndex.Put(ref.Slice(), clockBytes); err != nil {
		return err
	}

	log.Logger().Tracef("storing transaction logical clock, txRef: %s, clock: %d", ref.String(), clock)

	return nil
}

// getClock returns errNoClockValue if no clock value can be found for the given hash
func getClock(tx *bbolt.Tx, hash hash.SHA256Hash) (uint32, error) {
	lcIndex := tx.Bucket([]byte(clockIndexBucket))
	if lcIndex == nil {
		return 0, errNoClockValue
	}
	lClockBytes := lcIndex.Get(hash.Slice())
	if lClockBytes == nil {
		return 0, errNoClockValue
	}
	// can't be nil due to Previous must exist checks
	return bytesToClock(lClockBytes), nil
}

func bytesToClock(clockBytes []byte) uint32 {
	return binary.BigEndian.Uint32(clockBytes)
}

func clockToBytes(clock uint32) []byte {
	clockBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(clockBytes, clock)
	return clockBytes[:]
}

func getBuckets(tx *bbolt.Tx) (transactions, lc, lcIndex, payloadIndex, heads *bbolt.Bucket, err error) {
	if transactions, err = tx.CreateBucketIfNotExists([]byte(transactionsBucket)); err != nil {
		return
	}
	if lc, err = tx.CreateBucketIfNotExists([]byte(clockBucket)); err != nil {
		return
	}
	if lcIndex, err = tx.CreateBucketIfNotExists([]byte(clockIndexBucket)); err != nil {
		return
	}
	if payloadIndex, err = tx.CreateBucketIfNotExists([]byte(payloadIndexBucket)); err != nil {
		return
	}
	if heads, err = tx.CreateBucketIfNotExists([]byte(headsBucket)); err != nil {
		return
	}
	return
}

func getRoots(lcBucket *bbolt.Bucket) []hash.SHA256Hash {
	return parseHashList(lcBucket.Get(clockToBytes(0))) // no need to copy, calls FromSlice() (which copies)
}

func getTransaction(hash hash.SHA256Hash, tx *bbolt.Tx) (Transaction, error) {
	transactions := tx.Bucket([]byte(transactionsBucket))
	if transactions == nil {
		return nil, nil
	}
	clock, err := getClock(tx, hash)
	if err != nil {
		return nil, err
	}

	transactionBytes := copyBBoltValue(transactions, hash.Slice())
	if transactionBytes == nil {
		return nil, nil
	}
	parsedTx, err := ParseTransaction(transactionBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse transaction %s: %w", hash, err)
	}
	castTx := parsedTx.(*transaction)
	castTx.lamportClock = clock

	return parsedTx, nil
}

// exists checks whether the transaction with the given ref exists.
func exists(transactions *bbolt.Bucket, ref hash.SHA256Hash) bool {
	return transactions.Get(ref.Slice()) != nil
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

func notifyObservers(ctx context.Context, observers []Observer, subject interface{}) {
	for _, observer := range observers {
		observer(ctx, subject)
	}
}
