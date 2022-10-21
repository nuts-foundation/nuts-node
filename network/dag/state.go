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
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"sync/atomic"
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
// Multiple goroutines may invoke methods on a state simultaneously.
type state struct {
	db                  stoabs.KVStore
	graph               *dag
	payloadStore        PayloadStore
	txVerifiers         []Verifier
	notifiers           sync.Map
	xorTree             *treeStore
	ibltTree            *treeStore
	lamportClockHigh    atomic.Uint32
	transactionCount    prometheus.Counter
	eventsNotifyCount   prometheus.Counter
	eventsFinishedCount prometheus.Counter
}

func (s *state) Migrate() error {
	return s.graph.Migrate()
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
		xorTree:      newTreeStore(xorShelf, tree.New(tree.NewXor(), PageSize)),
		ibltTree:     newTreeStore(ibltShelf, tree.New(tree.NewIblt(IbltNumBuckets), PageSize)),
	}
	err := newState.initPrometheusCounters()
	if err != nil && err.Error() != (prometheus.AlreadyRegisteredError{}).Error() { // No unwrap on prometheus.AlreadyRegisteredError
		return nil, err
	}

	return newState, nil
}

func transactionCountCollector() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "nuts",
			Subsystem: "dag",
			Name:      "transactions_total",
			Help:      "Number of transactions stored in the DAG",
		},
	)
}

func (s *state) initPrometheusCounters() error {
	s.transactionCount = transactionCountCollector()
	err := prometheus.Register(s.transactionCount)
	if err != nil && err.Error() != (prometheus.AlreadyRegisteredError{}).Error() { // No unwrap on prometheus.AlreadyRegisteredError
		return err
	}
	s.eventsNotifyCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "nuts",
			Subsystem: "dag",
			Name:      "events_notified_total",
			Help:      "Number of DAG transaction notifications that were emitted (includes retries)",
		},
	)
	err = prometheus.Register(s.transactionCount)
	if err != nil && err.Error() != (prometheus.AlreadyRegisteredError{}).Error() { // No unwrap on prometheus.AlreadyRegisteredError
		return err
	}
	s.eventsFinishedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "nuts",
			Subsystem: "dag",
			Name:      "events_finished_total",
			Help:      "Number of DAG transaction notifications that were completed",
		},
	)
	err = prometheus.Register(s.transactionCount)
	if err != nil && err.Error() != (prometheus.AlreadyRegisteredError{}).Error() { // No unwrap on prometheus.AlreadyRegisteredError
		return err
	}

	return nil
}

func (s *state) Add(ctx context.Context, transaction Transaction, payload []byte) error {
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
	txAdded := false
	emitPayloadEvent := false

	// the tx may contain a large number of prevs. Reading those TXs inside the write-transaction may cause it to timeout.
	// See https://github.com/nuts-foundation/nuts-node/issues/1391
	var present bool
	if err := s.db.Read(ctx, func(tx stoabs.ReadTx) error {
		// Check TX presence before calling verifiers to avoid executing expensive checks (e.g. TXs with lots of prevs, signatures)
		// It does not prevent 100% of duplicate checks since race conditions may apply during a read TX.
		present = s.graph.isPresent(tx, transaction.Ref())
		if present {
			return nil
		}
		return s.verifyTX(tx, transaction)
	}); err != nil {
		return err
	}
	if present {
		// TX already present on DAG, nothing to do
		return nil
	}

	return s.db.Write(ctx, func(tx stoabs.WriteTx) error {
		// TX already present on DAG, nothing to do
		// We need to do this check again, because a concurrent call could've added the TX (e.g. we got it from another peer).
		// This is due to verifications being performed in a separate read-transaction above.
		// A TX must not be added twice, because it will corrupt the XOR and IBLT trees.
		if s.graph.isPresent(tx, transaction.Ref()) {
			return nil
		}

		// control the afterCommit hooks
		txAdded = true

		if payload != nil {
			emitPayloadEvent = true
			payloadHash := hash.SHA256Sum(payload)
			if !transaction.PayloadHash().Equals(payloadHash) {
				return errors.New("tx.PayloadHash does not match hash of payload")
			}
			if err := s.payloadStore.writePayload(tx, payloadHash, payload); err != nil {
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
		return s.updateState(tx, transaction)
	}, stoabs.OnRollback(func() {
		log.Logger().Warn("Reloading the XOR and IBLT trees due to a DB transaction Rollback")
		s.loadState(ctx)
	}), stoabs.AfterCommit(func() {
		if txAdded {
			s.notify(txEvent)
			if emitPayloadEvent {
				s.notify(payloadEvent)
			}
		}
	}), stoabs.AfterCommit(func() {
		if txAdded {
			s.transactionCount.Inc()
		}
	}), stoabs.WithWriteLock())
}

func (s *state) updateState(tx stoabs.WriteTx, transaction Transaction) error {
	clock := transaction.Clock()
	for {
		v := s.lamportClockHigh.Load()
		if v >= clock || s.lamportClockHigh.CompareAndSwap(v, clock) {
			break
		}
	}
	if err := s.ibltTree.write(tx, transaction); err != nil {
		return err
	}
	return s.xorTree.write(tx, transaction)
}

func (s *state) loadState(ctx context.Context) {
	if err := s.db.Read(ctx, func(tx stoabs.ReadTx) error {
		s.lamportClockHigh.Store(s.graph.getHighestClockValue(tx))
		if err := s.xorTree.read(tx); err != nil {
			return fmt.Errorf("failed to read xorTree: %w", err)
		}
		if err := s.ibltTree.read(tx); err != nil {
			return fmt.Errorf("failed to read ibltTree: %w", err)
		}
		return nil
	}); err != nil {
		log.Logger().
			WithError(err).
			Errorf("Failed to load the XOR and IBLT trees")
		return
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

func (s *state) FindBetweenLC(ctx context.Context, startInclusive uint32, endExclusive uint32) (transactions []Transaction, err error) {
	err = s.db.Read(ctx, func(tx stoabs.ReadTx) error {
		transactions, err = s.graph.findBetweenLC(tx, startInclusive, endExclusive)
		return err
	})
	return
}

func (s *state) GetTransaction(ctx context.Context, hash hash.SHA256Hash) (transaction Transaction, err error) {
	err = s.db.Read(ctx, func(tx stoabs.ReadTx) error {
		transaction, err = getTransaction(hash, tx)
		return err
	})
	return
}

func (s *state) IsPayloadPresent(ctx context.Context, hash hash.SHA256Hash) (present bool, err error) {
	err = s.db.Read(ctx, func(tx stoabs.ReadTx) error {
		present = s.payloadStore.isPayloadPresent(tx, hash)
		return nil
	})
	return
}

func (s *state) IsPresent(ctx context.Context, hash hash.SHA256Hash) (present bool, err error) {
	err = s.db.Read(ctx, func(tx stoabs.ReadTx) error {
		present = s.graph.isPresent(tx, hash)
		return nil
	})
	return
}

func (s *state) WritePayload(ctx context.Context, transaction Transaction, payloadHash hash.SHA256Hash, data []byte) error {
	event := Event{
		Type:        PayloadEventType,
		Hash:        transaction.Ref(),
		Retries:     0,
		Transaction: transaction,
		Payload:     data,
	}
	return s.db.Write(ctx, func(tx stoabs.WriteTx) error {
		if err := s.saveEvent(tx, event); err != nil {
			return err
		}
		return s.payloadStore.writePayload(tx, payloadHash, data)
	}, stoabs.AfterCommit(func() {
		s.notify(event)
	}), stoabs.WithWriteLock())
}

func (s *state) ReadPayload(ctx context.Context, hash hash.SHA256Hash) (payload []byte, err error) {
	err = s.db.Read(ctx, func(tx stoabs.ReadTx) error {
		payload, err = s.payloadStore.readPayload(tx, hash)
		return err
	})
	return
}

func (s *state) Head(ctx context.Context) (hash.SHA256Hash, error) {
	var head hash.SHA256Hash
	var err error
	err = s.db.Read(ctx, func(tx stoabs.ReadTx) error {
		head, err = s.graph.getHead(tx)
		return err
	})
	return head, err
}

// Notifier registers receiver under a unique name.
func (s *state) Notifier(name string, receiver ReceiverFn, options ...NotifierOption) (Notifier, error) {
	options = append(options, withCounters(s.eventsNotifyCount, s.eventsFinishedCount))

	n := NewNotifier(name, receiver, options...)

	_, loaded := s.notifiers.LoadOrStore(name, n)
	if loaded {
		return nil, fmt.Errorf("Nuts event receiver %q registration denied on duplicate name", name)
	}
	return n, nil
}

// Notifiers returns new slice with each registered instance in arbitrary order.
func (s *state) Notifiers() []Notifier {
	var a []Notifier
	s.notifiers.Range(func(_, value any) bool {
		a = append(a, value.(Notifier))
		return true
	})
	return a
}

func (s *state) XOR(reqClock uint32) (hash.SHA256Hash, uint32) {
	var data tree.Data

	currentClock := s.lamportClockHigh.Load()
	dataClock := currentClock
	if reqClock < currentClock {
		var pageClock uint32
		data, pageClock = s.xorTree.getZeroTo(reqClock)
		if pageClock < currentClock { // false on the last page
			dataClock = pageClock
		}
	} else {
		data = s.xorTree.getRoot()
	}

	return data.(*tree.Xor).Hash(), dataClock
}

func (s *state) IBLT(reqClock uint32) (tree.Iblt, uint32) {
	var data tree.Data

	currentClock := s.lamportClockHigh.Load()
	dataClock := currentClock
	if reqClock < currentClock {
		var pageClock uint32
		data, pageClock = s.ibltTree.getZeroTo(reqClock)
		if pageClock < currentClock { // false on the last page
			dataClock = pageClock
		}
	} else {
		data = s.ibltTree.getRoot()
	}

	return *data.(*tree.Iblt), dataClock
}

func (s *state) Shutdown() error {
	if s.transactionCount != nil {
		prometheus.Unregister(s.transactionCount)
	}
	return nil
}

func (s *state) Start() error {
	s.loadState(context.Background())

	err := s.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
		currentTXCount := s.graph.getNumberOfTransactions(tx)
		s.transactionCount.Add(float64(currentTXCount))
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to set initial transaction count metric: %w", err)
	}

	// resume all notifiers
	s.notifiers.Range(func(_, value any) bool {
		err = value.(Notifier).Run()
		return err == nil
	})
	return err
}

/*
Rebuild walks the DAG and validates that derived data (everything not on the transactionsShelf) is consistent with the DAG (transactionsShelf). Any incorrect derived data is corrected.

Validation and correction is done in 2 steps.
First the DAG is rebuild by locking the DAG with a stoabs.WithWriteLock and walking the entire thing to fix any mistakes on the clockShelf + metadataShelf.
Then the clockShelf is walked page-by-page to rebuild the state trees, where each page is processed in the context of a stoabs.WithWriteLock to ensure corrections are still valid when they are applied.

The DAG is thus walked twice, potentially locking the database for a long time.

Shelfs:

  - transactionsShelf: this is the actual DAG and is leading. TODO: should signatures be verified here?

  - clockShelf: maps lamport clock values to transaction references.

  - metadataShelf:
    -> highestClock: updated first since it is part of the loop condition.
    -> headRef: handle to 'prev' for a new transactions. No deterministic way to select "correct" head, so assumed correct if head is in any of the Txs with highestClock.
    -> numTransactions: total transaction in the DAG. Hard to fix since any 'historical' additions to the DAG during a 'batched' Rebuild will be missed.

  - ibltShelf + xorShelf: summarizes the DAG one PageSize at a time. Raw data for the state.ibltTree and state.xorTree. Fixing this from the clockShelf saves unmarshalling of all transactions, but clockShelf is derived data as well.
*/
func (s *state) Rebuild(ctx context.Context) error {
	if err := s.db.Write(ctx, s.graph.rebuild, stoabs.WithWriteLock()); err != nil {
		return err
	}
	return s.rebuildTrees(ctx)
}

// rebuildTrees runs on the clockShelf since this shelf contains all data needed, prevents parsing of all transactions, and would be used in any LC based query on the DAG anyway.
// This requires/assumes the clockShelf to be in sync with the transactionsShelf.
func (s *state) rebuildTrees(ctx context.Context) error {
	var err error
	var ibltDAG *tree.Iblt // truth from the DAG
	var xorDAG *tree.Xor   // truth from the DAG
	//var ibltState, xorState tree.Data // currently in State
	var clockMap map[uint32][]hash.SHA256Hash
	var hashes []hash.SHA256Hash
	var lastLC uint32

	// reload state to make sure disk-state and mem-state are the same
	s.loadState(ctx)

	// loop over DAG page-by-page
	keepWalking := true
	for pageStart := uint32(0); keepWalking; pageStart += PageSize { // TODO: does this get the current highestLC at every iteration of the loop?
		// reset loop values
		ibltDAG = tree.NewIblt(IbltNumBuckets)
		xorDAG = tree.NewXor()

		// read a page of txs, and a page of the trees
		err = s.db.Write(ctx, func(tx stoabs.WriteTx) error {
			// collect data over a single page of the DAG
			clockMap, err = s.graph.findHashesBetweenLC(tx, pageStart, pageStart+PageSize)
			if err != nil {
				return err
			}
			for clock := pageStart; clock < pageStart+PageSize; clock++ {
				hashes = clockMap[clock]
				if len(hashes) == 0 {
					// reached the end of the DAG
					keepWalking = false
					break
				}

				lastLC = clock
				for i, _ := range hashes {
					ibltDAG.Insert(hashes[i])
					xorDAG.Insert(hashes[i])
				}
			}

			if !keepWalking {
				// NOTE: there is a 1:PageSize chance this doesn't happen under the same write lock.
				// graph.rebuild + graph.rebuildMetadataShelf fixes the clock in a safe way
				if s.lamportClockHigh.Load() != lastLC {
					// TODO: add logging
					s.lamportClockHigh.Store(lastLC)
					if err = s.graph.setHighestClockValue(tx, lastLC); err != nil {
						return err
					}
				}
				// TODO: might be possible to rebuild the metadataShelf from here
			}

			// get data from a single page of the trees and compare to the DAG.
			// Must be done within the context of the WriteLock so any errors can be corrected immediately.
			if err = s.ibltTree.rebuildPage(tx, pageStart, ibltDAG); err != nil {
				return err
			}
			if err = s.xorTree.rebuildPage(tx, pageStart, xorDAG); err != nil {
				return err
			}

			return nil
		}, stoabs.OnRollback(func() {
			s.loadState(ctx)
		}), stoabs.WithWriteLock())
		if err != nil {
			return err
		}
	}

	return nil
}

// Verify can be used to verify the entire DAG.
// TODO problematic for large sets. Currently not used, see #1216
func (s *state) Verify(ctx context.Context) error {
	return s.db.Read(ctx, func(dbTx stoabs.ReadTx) error {
		transactions, err := s.graph.findBetweenLC(dbTx, 0, MaxLamportClock)
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

func (s *state) saveEvent(tx stoabs.WriteTx, event Event) error {
	var err error
	s.notifiers.Range(func(_, value any) bool {
		err := value.(Notifier).Save(tx, event)
		return err == nil
	})
	return err
}

func (s *state) notify(event Event) {
	s.notifiers.Range(func(_, value any) bool {
		value.(Notifier).Notify(event)
		return true
	})
}

func (s *state) failedEventCount() int {
	var n int
	s.notifiers.Range(func(key, value any) bool {
		events, err := value.(Notifier).GetFailedEvents()
		if err != nil {
			log.Logger().WithError(err).Errorf("failed events from %q omitted", key)
		}
		n += len(events)
		return true
	})
	return n
}

func (s *state) Diagnostics() []core.DiagnosticResult {
	diag := s.graph.diagnostics(context.Background())
	diag = append(diag, &core.GenericDiagnosticResult{Title: "dag_xor", Outcome: s.xorTree.getRoot().(*tree.Xor).Hash()})
	diag = append(diag, &core.GenericDiagnosticResult{Title: "failed_events", Outcome: s.failedEventCount()})
	return diag
}
