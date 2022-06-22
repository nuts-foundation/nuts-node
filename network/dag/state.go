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
	"math"
	"sync"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/network/log"
)

const (
	// PageSize specifies the Lamport Clock range over which data is summarized and is used in set reconciliation.
	PageSize = uint32(512)
	// IbltNumBuckets is the number of buckets in the IBLT used in set reconciliation.
	IbltNumBuckets = 1024
	xorShelf       = "xorBucket"
	ibltShelf      = "ibltBucket"
)

// State has references to the DAG and the payload store.
type state struct {
	db                               stoabs.KVStore
	graph                            *dag
	payloadStore                     PayloadStore
	transactionalObservers           []Observer
	nonTransactionalObservers        []Observer
	transactionalPayloadObservers    []PayloadObserver
	nonTransactionalPayloadObservers []PayloadObserver
	txVerifiers                      []Verifier
	notifiers                        map[string]Notifier
	xorTree                          *treeStore
	ibltTree                         *treeStore
	treeMux                          sync.Mutex
}

// NewState returns a new State. The State is used as entry point, it's methods will start transactions and will notify observers from within those transactions.
func NewState(db stoabs.KVStore, verifiers ...Verifier) (State, error) {
	graph := newDAG(db)

	payloadStore := NewPayloadStore()
	newState := &state{
		db:           db,
		graph:        graph,
		payloadStore: payloadStore,
		txVerifiers:  verifiers,
		notifiers:    map[string]Notifier{},
	}

	return newState, nil
}

func initShelfs(db stoabs.KVStore, shelfs ...string) error {
	// TODO: replace with shelf initialization method that is agnostic to the underlying store. See https://github.com/nuts-foundation/go-stoabs/issues/14
	for _, shelf := range shelfs {
		if err := db.WriteShelf(shelf, func(writer stoabs.Writer) error {
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
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

func (s *state) Add(_ context.Context, transaction Transaction, payload []byte) error {
	txEvent := Event{
		Type:        TransactionEventType,
		Hash:        transaction.Ref(),
		Retries:     0,
		Transaction: transaction,
		Payload:     payload,
	}
	payloadEvent := Event{
		Type:        PayloadEventType,
		Hash:        transaction.Ref(),
		Retries:     0,
		Transaction: transaction,
		Payload:     payload,
	}
	emitPayloadEvent := false

	return s.db.Write(func(tx stoabs.WriteTx) error {
		present := s.graph.isPresent(tx, transaction.Ref())
		if present {
			return nil
		}

		if err := s.verifyTX(tx, transaction); err != nil {
			return err
		}
		if payload != nil {
			emitPayloadEvent = true
			payloadHash := hash.SHA256Sum(payload)
			if !transaction.PayloadHash().Equals(payloadHash) {
				return errors.New("tx.PayloadHash does not match hash of payload")
			}
			if err := s.writePayload(tx, transaction, payloadHash, payload); err != nil {
				return err
			}
			if err := s.saveEvent(tx, payloadEvent); err != nil {
				return err
			}
		}
		if err := s.graph.add(tx, transaction); err != nil {
			return err
		}
		if err := s.saveEvent(tx, txEvent); err != nil {
			return err
		}

		// update XOR and IBLT
		if err := s.updateTrees(tx, transaction); err != nil {
			return err
		}

		return s.notifyObservers(tx, transaction)
	}, stoabs.OnRollback(func() {
		log.Logger().Warn("Reloading the XOR and IBLT trees due to a DB transaction Rollback")
		s.loadTrees()
	}), stoabs.AfterCommit(func() {
		s.notify(txEvent)
		if emitPayloadEvent {
			s.notify(payloadEvent)
		}
	}),
	)
}

func (s *state) updateTrees(tx stoabs.WriteTx, transaction Transaction) error {
	s.treeMux.Lock()
	defer s.treeMux.Unlock()

	if err := s.ibltTree.write(tx, transaction); err != nil {
		return err
	}
	return s.xorTree.write(tx, transaction)
}

func (s *state) loadTrees() {
	s.treeMux.Lock()
	defer s.treeMux.Unlock()
	if err := s.db.Read(func(tx stoabs.ReadTx) error {
		s.xorTree = newTreeStore(xorShelf, tree.New(tree.NewXor(), PageSize))
		s.ibltTree = newTreeStore(ibltShelf, tree.New(tree.NewIblt(IbltNumBuckets), PageSize))

		if err := s.xorTree.read(tx); err != nil {
			return fmt.Errorf("failed to read xorTree: %w", err)
		}

		if err := s.ibltTree.read(tx); err != nil {
			return fmt.Errorf("failed to read ibltTree: %w", err)
		}
		return nil
	}); err != nil {
		log.Logger().Errorf("Failed to load the XOR and IBLT trees: %s", err)
	}
	log.Logger().Trace("Loaded the XOR and IBLT trees")
}

func (s *state) verifyTX(tx stoabs.ReadTx, transaction Transaction) error {
	for _, verifier := range s.txVerifiers {
		if err := verifier(tx, transaction); err != nil {
			return fmt.Errorf("transaction verification failed (tx=%s): %w", transaction.Ref(), err)
		}
	}
	return nil
}

func (s *state) FindBetweenLC(startInclusive uint32, endExclusive uint32) (transactions []Transaction, err error) {
	err = s.db.Read(func(tx stoabs.ReadTx) error {
		transactions, err = s.graph.findBetweenLC(tx, startInclusive, endExclusive)
		return err
	})
	return
}

func (s *state) GetTransaction(_ context.Context, hash hash.SHA256Hash) (transaction Transaction, err error) {
	err = s.db.Read(func(tx stoabs.ReadTx) error {
		transaction, err = getTransaction(hash, tx)
		return err
	})
	return
}

func (s *state) IsPayloadPresent(_ context.Context, hash hash.SHA256Hash) (present bool, err error) {
	err = s.db.Read(func(tx stoabs.ReadTx) error {
		present = s.payloadStore.isPayloadPresent(tx, hash)
		return nil
	})
	return
}

func (s *state) IsPresent(_ context.Context, hash hash.SHA256Hash) (present bool, err error) {
	err = s.db.Read(func(tx stoabs.ReadTx) error {
		present = s.graph.isPresent(tx, hash)
		return nil
	})
	return
}

func (s *state) WritePayload(transaction Transaction, payloadHash hash.SHA256Hash, data []byte) error {
	return s.db.Write(func(tx stoabs.WriteTx) error {
		return s.writePayload(tx, transaction, payloadHash, data)
	})
}

func (s *state) writePayload(tx stoabs.WriteTx, transaction Transaction, payloadHash hash.SHA256Hash, data []byte) error {
	err := s.payloadStore.writePayload(tx, payloadHash, data)
	if err == nil {
		// ctx passed with bbolt transaction
		return s.notifyPayloadObservers(transaction, data)
	}
	return err
}

func (s *state) ReadPayload(_ context.Context, hash hash.SHA256Hash) (payload []byte, err error) {
	_ = s.db.Read(func(tx stoabs.ReadTx) error {
		payload, err = s.payloadStore.readPayload(tx, hash)
		return err
	})
	return
}

func (s *state) Heads(_ context.Context) []hash.SHA256Hash {
	heads := make([]hash.SHA256Hash, 0)
	_ = s.db.Read(func(tx stoabs.ReadTx) error {
		heads = s.graph.heads(tx)
		return nil
	})
	return heads
}

func (s *state) Notifier(name string, receiver ReceiverFn, options ...NotifierOption) (Notifier, error) {
	if _, exists := s.notifiers[name]; exists {
		return nil, fmt.Errorf("notifier already exists (name=%s)", name)
	}

	notifier := NewNotifier(name, receiver, options...)
	s.notifiers[name] = notifier

	return notifier, nil
}

func (s *state) XOR(_ context.Context, reqClock uint32) (hash.SHA256Hash, uint32) {
	var data tree.Data

	currentClock := s.lamportClock()
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

func (s *state) IBLT(_ context.Context, reqClock uint32) (tree.Iblt, uint32) {
	var data tree.Data

	currentClock := s.lamportClock()
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
func (s *state) lamportClock() uint32 {
	return s.graph.getHighestClock()
}

func (s *state) Shutdown() error {
	return nil
}

func (s *state) Start() error {
	// initialize all shelfs so that the db cannot return nil readers
	err := initShelfs(s.db, transactionsShelf, headsShelf, clockShelf, payloadsShelf, ibltShelf, xorShelf)
	if err != nil {
		return err
	}
	s.loadTrees()

	if err := s.Verify(); err != nil {
		return err
	}

	// resume all notifiers
	for _, notifier := range s.notifiers {
		if err := notifier.Run(); err != nil {
			return err
		}
	}

	return nil
}

func (s *state) Statistics(_ context.Context) Statistics {
	var stats Statistics
	_ = s.db.Read(func(tx stoabs.ReadTx) error {
		stats = s.graph.statistics(tx)
		return nil
	})
	return stats
}

func (s *state) Verify() error {
	return s.db.Read(func(dbTx stoabs.ReadTx) error {
		transactions, err := s.graph.findBetweenLC(dbTx, 0, math.MaxUint32)
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

func (s *state) Walk(_ context.Context, visitor Visitor, startAt uint32) error {
	return s.db.Read(func(tx stoabs.ReadTx) error {
		return s.graph.walk(tx, startAt, func(transaction Transaction) bool {
			return visitor(transaction)
		})
	})
}

// notifyObservers is called from a transactional context. The transactional observers need to be called with the TX context, the other observers after the commit.
func (s *state) notifyObservers(tx stoabs.WriteTx, transaction Transaction) error {
	// apply TX context observers
	for _, observer := range s.transactionalObservers {
		if err := observer(tx, transaction); err != nil {
			return fmt.Errorf("observer notification failed: %w", err)
		}
	}

	notifyNonTXObservers := func() {
		for _, observer := range s.nonTransactionalObservers {
			if err := observer(tx, transaction); err != nil {
				log.Logger().Errorf("observer notification failed: %v", err)
			}
		}
	}
	notifyNonTXObservers()
	return nil
}

func (s *state) notifyPayloadObservers(transaction Transaction, payload []byte) error {
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
	notifyNonTXObservers()
	return nil
}

func (s *state) saveEvent(tx stoabs.WriteTx, event Event) error {
	for _, notifier := range s.notifiers {
		if err := notifier.Save(tx, event); err != nil {
			return err
		}
	}

	return nil
}

func (s *state) notify(event Event) {
	for _, notifier := range s.notifiers {
		notifier.Notify(event)
	}
}

func (s *state) Diagnostics() []core.DiagnosticResult {
	diag := s.graph.diagnostics()
	diag = append(diag, &core.GenericDiagnosticResult{Title: "dag_xor", Outcome: s.xorTree.getRoot().(*tree.Xor).Hash()})
	return diag
}
