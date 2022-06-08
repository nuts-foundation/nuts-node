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

package dag

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/storage"
	"go.etcd.io/bbolt"
)

const (
	// boltDBFileMode holds the Unix file mode the created BBolt database files will have.
	boltDBFileMode = 0600
	// PageSize specifies the Lamport Clock range over which data is summarized and is used in set reconciliation.
	PageSize = uint32(512)
	// IbltNumBuckets is the number of buckets in the IBLT used in set reconciliation.
	IbltNumBuckets = 1024
)

// State has references to the DAG and the payload store.
type state struct {
	db                               *bbolt.DB
	graph                            *bboltDAG
	payloadStore                     PayloadStore
	transactionalObservers           []Observer
	nonTransactionalObservers        []Observer
	transactionalPayloadObservers    []PayloadObserver
	nonTransactionalPayloadObservers []PayloadObserver
	publisher                        Publisher
	txVerifiers                      []Verifier
	xorTree                          *bboltTree
	ibltTree                         *bboltTree
}

// NewState returns a new State. The State is used as entry point, it's methods will start transactions and will notify observers from within those transactions.
func NewState(dataDir string, verifiers ...Verifier) (State, error) {
	dbFile := path.Join(dataDir, "network", "data.db")
	if err := os.MkdirAll(filepath.Dir(dbFile), os.ModePerm); err != nil {
		return nil, fmt.Errorf("unable to create BBolt database: %w", err)
	}

	var bboltErr error
	db, bboltErr := bbolt.Open(dbFile, boltDBFileMode, bbolt.DefaultOptions)
	if bboltErr != nil {
		return nil, fmt.Errorf("unable to create BBolt database: %w", bboltErr)
	}

	graph := newBBoltDAG(db)

	payloadStore := NewBBoltPayloadStore(db)
	newState := &state{
		db:           db,
		graph:        graph,
		payloadStore: payloadStore,
		txVerifiers:  verifiers,
	}

	publisher := NewReplayingDAGPublisher(payloadStore, graph)
	publisher.ConfigureCallbacks(newState)
	newState.publisher = publisher

	xorTree := newBBoltTreeStore(db, "xorBucket", tree.New(tree.NewXor(), PageSize))
	ibltTree := newBBoltTreeStore(db, "ibltBucket", tree.New(tree.NewIblt(IbltNumBuckets), PageSize))
	newState.xorTree = xorTree
	newState.ibltTree = ibltTree
	newState.RegisterTransactionObserver(newState.treeObserver, true)

	return newState, nil
}

func (s *state) RegisterTransactionObserver(observer Observer, transactional bool) {
	if transactional {
		s.transactionalObservers = append(s.transactionalObservers, observer)
	} else {
		s.nonTransactionalObservers = append(s.nonTransactionalObservers, observer)
	}
}

func (s *state) RegisterPayloadObserver(observer PayloadObserver, transactional bool) {
	if transactional {
		s.transactionalPayloadObservers = append(s.transactionalPayloadObservers, observer)
	} else {
		s.nonTransactionalPayloadObservers = append(s.nonTransactionalPayloadObservers, observer)
	}
}

func (s *state) treeObserver(ctx context.Context, transaction Transaction) error {
	if err := s.ibltTree.dagObserver(ctx, transaction, nil); err != nil {
		return err
	}
	return s.xorTree.dagObserver(ctx, transaction, nil)
}

func (s *state) Add(ctx context.Context, transaction Transaction, payload []byte) error {
	return storage.BBoltTXUpdate(ctx, s.db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
		present := s.graph.isPresent(tx, transaction.Ref())
		if present {
			return nil
		}

		if err := s.verifyTX(tx, transaction); err != nil {
			return err
		}
		if payload != nil {
			payloadHash := hash.SHA256Sum(payload)
			if !transaction.PayloadHash().Equals(payloadHash) {
				return errors.New("tx.PayloadHash does not match hash of payload")
			}
			if err := s.writePayload(tx, transaction, payloadHash, payload); err != nil {
				return err
			}
		}
		if err := s.graph.add(tx, transaction); err != nil {
			return err
		}

		return s.notifyObservers(contextWithTX, transaction)
	})
}

func (s *state) verifyTX(tx *bbolt.Tx, transaction Transaction) error {
	for _, verifier := range s.txVerifiers {
		if err := verifier(tx, transaction); err != nil {
			return fmt.Errorf("transaction verification failed (tx=%s): %w", transaction.Ref(), err)
		}
	}
	return nil
}

func (s *state) FindBetween(startInclusive time.Time, endExclusive time.Time) (transactions []Transaction, err error) {
	err = s.db.View(func(tx *bbolt.Tx) error {
		transactions, err = s.graph.findBetween(tx, startInclusive, endExclusive)
		return err
	})
	return
}

func (s *state) FindBetweenLC(startInclusive uint32, endExclusive uint32) (transactions []Transaction, err error) {
	err = s.db.View(func(tx *bbolt.Tx) error {
		transactions, err = s.graph.findBetweenLC(tx, startInclusive, endExclusive)
		return err
	})
	return
}

func (s *state) GetTransaction(ctx context.Context, hash hash.SHA256Hash) (transaction Transaction, err error) {
	err = storage.BBoltTXView(ctx, s.db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
		transaction, err = getTransaction(hash, tx)
		return err
	})
	return
}

func (s *state) IsPayloadPresent(ctx context.Context, hash hash.SHA256Hash) (present bool, err error) {
	err = storage.BBoltTXView(ctx, s.db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
		present = s.payloadStore.isPayloadPresent(tx, hash)
		return nil
	})
	return
}

func (s *state) IsPresent(ctx context.Context, hash hash.SHA256Hash) (present bool, err error) {
	err = storage.BBoltTXView(ctx, s.db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
		present = s.graph.isPresent(tx, hash)
		return nil
	})
	return
}

func (s *state) WritePayload(transaction Transaction, payloadHash hash.SHA256Hash, data []byte) error {
	return storage.BBoltTXUpdate(context.Background(), s.db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
		return s.writePayload(tx, transaction, payloadHash, data)
	})
}

func (s *state) writePayload(tx *bbolt.Tx, transaction Transaction, payloadHash hash.SHA256Hash, data []byte) error {
	err := s.payloadStore.writePayload(tx, payloadHash, data)
	if err == nil {
		// ctx passed with bbolt transaction
		return s.notifyPayloadObservers(tx, transaction, data)
	}
	return err
}

func (s *state) ReadPayload(ctx context.Context, hash hash.SHA256Hash) (payload []byte, err error) {
	err = storage.BBoltTXView(ctx, s.db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
		payload = s.payloadStore.readPayload(tx, hash)
		return nil
	})
	return
}

func (s *state) Subscribe(eventType EventType, payloadType string, receiver Receiver) {
	s.publisher.Subscribe(eventType, payloadType, receiver)
}

func (s *state) Heads(ctx context.Context) []hash.SHA256Hash {
	return s.graph.heads(ctx)
}

func (s *state) XOR(ctx context.Context, reqClock uint32) (hash.SHA256Hash, uint32) {
	var data tree.Data

	currentClock := s.lamportClock(ctx)
	dataClock := currentClock
	if reqClock < currentClock {
		var pageClock uint32
		data, pageClock = s.xorTree.tree.GetZeroTo(reqClock)
		if pageClock < currentClock { // false on the last page
			dataClock = pageClock
		}
	} else {
		data = s.xorTree.tree.GetRoot()
	}

	return data.(*tree.Xor).Hash(), dataClock
}

func (s *state) IBLT(ctx context.Context, reqClock uint32) (tree.Iblt, uint32) {
	var data tree.Data

	currentClock := s.lamportClock(ctx)
	dataClock := currentClock
	if reqClock < currentClock {
		var pageClock uint32
		data, pageClock = s.ibltTree.tree.GetZeroTo(reqClock)
		if pageClock < currentClock { // false on the last page
			dataClock = pageClock
		}
	} else {
		data = s.ibltTree.tree.GetRoot()
	}

	return *data.(*tree.Iblt), dataClock
}

// lamportClock returns the highest clock value in the DAG.
func (s *state) lamportClock(ctx context.Context) uint32 {
	// TODO: keep track of clock in state
	return s.graph.getHighestClock(ctx)
}

func (s *state) Shutdown() error {
	// Close BBolt database
	if s.db != nil {
		err := s.db.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *state) Start() error {
	ctx := context.Background()
	// load trees or build if they do not exist yet.
	// can only build after DAG migration added clock values for all transactions and before the publisher starts
	if err := s.xorTree.read(ctx); err != nil {
		return fmt.Errorf("failed to read xorTree: %w", err)
	}

	if err := s.ibltTree.read(ctx); err != nil {
		return fmt.Errorf("failed to read ibltTree: %w", err)
	}

	if err := s.publisher.Start(); err != nil {
		return err
	}

	if err := s.Verify(); err != nil {
		return err
	}

	return nil
}

func (s *state) Statistics(ctx context.Context) Statistics {
	return s.graph.statistics(ctx)
}

func (s *state) Verify() error {
	return storage.BBoltTXView(context.Background(), s.db, func(contextWithTX context.Context, dbTx *bbolt.Tx) error {
		transactions, err := s.graph.findBetween(dbTx, MinTime(), MaxTime())
		if err != nil {
			return err
		}
		for _, tx := range transactions {
			if err := s.verifyTX(dbTx, tx); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *state) Walk(ctx context.Context, visitor Visitor, startAt hash.SHA256Hash) error {
	return storage.BBoltTXView(ctx, s.db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
		return s.graph.walk(tx, func(tx *bbolt.Tx, transaction Transaction) bool {
			return visitor(transaction)
		}, startAt)
	})
}

// notifyObservers is called from a transactional context. The transactional observers need to be called with the TX context, the other observers after the commit.
func (s *state) notifyObservers(ctx context.Context, transaction Transaction) error {
	// apply TX context observers
	for _, observer := range s.transactionalObservers {
		if err := observer(ctx, transaction); err != nil {
			return fmt.Errorf("observer notification failed: %w", err)
		}
	}

	notifyNonTXObservers := func() {
		for _, observer := range s.nonTransactionalObservers {
			if err := observer(context.Background(), transaction); err != nil {
				log.Logger().Errorf("observer notification failed: %v", err)
			}
		}
	}
	// check if there's an active transaction
	tx, txIsActive := storage.BBoltTX(ctx)
	if txIsActive { // sanity check because there should always be a transaction
		tx.OnCommit(notifyNonTXObservers)
	} else {
		notifyNonTXObservers()
	}
	return nil
}

func (s *state) notifyPayloadObservers(tx *bbolt.Tx, transaction Transaction, payload []byte) error {
	// apply TX context observers
	for _, observer := range s.transactionalPayloadObservers {
		if err := observer(transaction, payload); err != nil {
			return fmt.Errorf("observer notification failed: %w", err)
		}
	}

	notifyNonTXObservers := func() {
		for _, observer := range s.nonTransactionalPayloadObservers {
			if err := observer(transaction, payload); err != nil {
				log.Logger().Errorf("observer notification failed: %v", err)
			}
		}
	}
	// check if there's an active transaction
	tx.OnCommit(notifyNonTXObservers)
	return nil
}

func (s *state) Diagnostics() []core.DiagnosticResult {
	diag := s.graph.diagnostics()
	diag = append(diag, &core.GenericDiagnosticResult{Title: "dag_xor", Outcome: s.xorTree.getRoot().(*tree.Xor).Hash()})
	return diag
}
