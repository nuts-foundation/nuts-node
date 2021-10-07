/*
 * Copyright (C) 2021. Nuts community
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
			result, err = getTransaction(ref, transactions)
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
			transaction, err := getTransaction(transactionHash, transactions)
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
	rootTX, err := dag.Root(ctx)
	if err != nil {
		return nil, err
	}
	err = dag.Walk(ctx, NewBFSWalkerAlgorithm(), func(ctx context.Context, transaction Transaction) bool {
		if !transaction.SigningTime().Before(startInclusive) && transaction.SigningTime().Before(endExclusive) {
			result = append(result, transaction)
		}
		return true
	}, rootTX)
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

func (dag bboltDAG) Walk(ctx context.Context, algo WalkerAlgorithm, visitor Visitor, startAt hash.SHA256Hash) error {
	return bboltTXView(ctx, dag.db, func(ctx context.Context, tx *bbolt.Tx) error {
		transactions := tx.Bucket([]byte(transactionsBucket))
		nexts := tx.Bucket([]byte(nextsBucket))
		if transactions == nil || nexts == nil {
			// DAG is empty
			return nil
		}
		return algo.walk(ctx, visitor, startAt, func(hash hash.SHA256Hash) (Transaction, error) {
			return getTransaction(hash, transactions)
		}, func(hash hash.SHA256Hash) ([]hash.SHA256Hash, error) {
			return parseHashList(nexts.Get(hash.Slice())), nil // no need to copy, calls FromSlice() (which copies)
		})
	})
}

func (dag bboltDAG) Root(ctx context.Context) (hash hash.SHA256Hash, err error) {
	err = bboltTXView(ctx, dag.db, func(ctx context.Context, tx *bbolt.Tx) error {
		if transactions := tx.Bucket([]byte(transactionsBucket)); transactions != nil {
			if roots := getRoots(transactions); len(roots) >= 1 {
				hash = roots[0]
			}
		}
		return nil
	})
	return
}

func (dag bboltDAG) Statistics(ctx context.Context) Statistics {
	transactionNum := 0
	_ = bboltTXView(ctx, dag.db, func(ctx context.Context, tx *bbolt.Tx) error {
		if bucket := tx.Bucket([]byte(transactionsBucket)); bucket != nil {
			// There's an extra entry in the Bucket for the root transaction,
			// which is just a reference to the actual root transaction. So we subtract 1 from the number of keys to get
			// the real number of TXs
			transactionNum = bucket.Stats().KeyN - 1
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
		transactions, nexts, payloadIndex, heads, err := getBuckets(tx)
		if err != nil {
			return err
		}
		if exists(transactions, ref) {
			log.Logger().Tracef("Transaction %s already exists, not adding it again.", ref)
			return nil
		}
		if len(transaction.Previous()) == 0 {
			if getRoots(transactions) != nil {
				return errRootAlreadyExists
			}
			if err := addRoot(transactions, ref); err != nil {
				return fmt.Errorf("unable to register root %s: %w", ref, err)
			}
		}
		if err := transactions.Put(refSlice, transaction.Data()); err != nil {
			return err
		}
		// Store forward references ([C -> prev A, B] is stored as [A -> C, B -> C])
		for _, prev := range transaction.Previous() {
			if err := dag.registerNextRef(nexts, prev, ref); err != nil {
				return fmt.Errorf("unable to store forward reference %s->%s: %w", prev, ref, err)
			}
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

func getBuckets(tx *bbolt.Tx) (transactions, nexts, payloadIndex, heads *bbolt.Bucket, err error) {
	if transactions, err = tx.CreateBucketIfNotExists([]byte(transactionsBucket)); err != nil {
		return
	}
	if nexts, err = tx.CreateBucketIfNotExists([]byte(nextsBucket)); err != nil {
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

func getRoots(transactionsBucket *bbolt.Bucket) []hash.SHA256Hash {
	return parseHashList(transactionsBucket.Get([]byte(rootsTransactionKey))) // no need to copy, calls FromSlice() (which copies)
}

func addRoot(transactionsBucket *bbolt.Bucket, ref hash.SHA256Hash) error {
	roots := appendHashList(transactionsBucket.Get([]byte(rootsTransactionKey)), ref)
	return transactionsBucket.Put([]byte(rootsTransactionKey), roots)
}

// registerNextRef registers a forward reference a.k.a. "next", in contrary to "prev(s)" which is the inverse of the relation.
// It takes the nexts bucket, the prev and the next. Given transaction A and B where B prevs A, prev = A, next = B.
func (dag *bboltDAG) registerNextRef(nextsBucket *bbolt.Bucket, prev hash.SHA256Hash, next hash.SHA256Hash) error {
	prevSlice := prev.Slice()
	value := nextsBucket.Get(prevSlice)
	if value == nil {
		// No entry yet for this prev
		return nextsBucket.Put(prevSlice, next.Slice())
	}
	// Existing entry for this prev so add this one to it
	return nextsBucket.Put(prevSlice, appendHashList(value, next))
}

func getTransaction(hash hash.SHA256Hash, transactions *bbolt.Bucket) (Transaction, error) {
	transactionBytes := copyBBoltValue(transactions, hash.Slice())
	if transactionBytes == nil {
		return nil, nil
	}
	transaction, err := ParseTransaction(transactionBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse transaction %s: %w", hash, err)
	}
	return transaction, nil
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
