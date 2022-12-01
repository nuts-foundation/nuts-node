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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/vdr/types"
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
	graph               *dag
	payloadPerHash      map[hash.SHA256Hash]string
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
	return nil // nop
}

// NewState returns a new State. The State is used as entry point, it's methods will start transactions and will notify observers from within those transactions.
func NewState() State {
	graph := newDAG()

	newState := &state{
		graph:          graph,
		payloadPerHash: make(map[hash.SHA256Hash]string),
		xorTree:        newTreeStore(tree.New(tree.NewXor(), PageSize)),
		ibltTree:       newTreeStore(tree.New(tree.NewIblt(IbltNumBuckets), PageSize)),
	}
	// TODO: Better Prometheus library github.com/pascaldekloe/metrics
	// to prevent error scenario.
	err := newState.initPrometheusCounters()
	if err != nil && err.Error() != (prometheus.AlreadyRegisteredError{}).Error() { // No unwrap on prometheus.AlreadyRegisteredError
		log.Logger().WithError(err).Fatal("exit on Prometheus")
	}

	return newState
}

func NewStateWithVerifiers(keyr types.KeyResolver) State {
	n := NewState()
	n.(*state).txVerifiers = append(n.(*state).txVerifiers,
		newPrevTransactionsVerifier(n.(*state).graph),
		newTransactionSignatureVerifier(keyr),
	)
	return n
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

func (s *state) Add(ctx context.Context, tx Transaction, payload []byte) error {
	txEvent := Event{
		Type:        TransactionEventType,
		Hash:        tx.Ref(),
		Retries:     0,
		Transaction: tx,
		Payload:     payload,
	}
	payloadEvent := Event{
		Type:        PayloadEventType,
		Hash:        tx.Ref(),
		Retries:     0,
		Transaction: tx,
		Payload:     payload,
	}

	if s.graph.containsTxHash(tx.Ref()) {
		// TX already present on DAG, nothing to do
		return nil
	}

	// Check TX presence before calling verifiers to avoid executing expensive checks (e.g. TXs with lots of prevs, signatures)
	// It does not prevent 100% of duplicate checks since race conditions may apply during a read TX.
	if err := s.verifyTx(tx); err != nil {
		return err
	}
	if payload != nil {
		payloadHash := hash.SHA256Sum(payload)
		if !tx.PayloadHash().Equals(payloadHash) {
			return errors.New("tx.PayloadHash does not match hash of payload")
		}

		s.payloadPerHash[hash.SHA256Sum(payload)] = string(payload)
		if err := s.saveEvent(payloadEvent); err != nil {
			return err
		}
		s.notify(payloadEvent)
	}

	if err := s.graph.addTx(tx); err != nil {
		return err
	}
	s.transactionCount.Inc()

	if err := s.saveEvent(txEvent); err != nil {
		return err
	}
	s.notify(txEvent)

	// update XOR and IBLT
	s.updateState(tx)
	return nil
}

func (s *state) updateState(transaction Transaction) {
	clock := transaction.Clock()
	for {
		v := s.lamportClockHigh.Load()
		if v >= clock || s.lamportClockHigh.CompareAndSwap(v, clock) {
			break
		}
	}
	s.ibltTree.insert(transaction)
	s.xorTree.insert(transaction)
}

func (s *state) verifyTx(tx Transaction) error {
	for _, verifier := range s.txVerifiers {
		if err := verifier(tx); err != nil {
			return fmt.Errorf("transaction verification failed (tx=%s): %w", tx.Ref(), err)
		}
	}
	return nil
}

func (s *state) FindBetweenLC(ctx context.Context, startInclusive uint32, endExclusive uint32) (transactions []Transaction, err error) {
	return s.graph.findBetweenLC(startInclusive, endExclusive), nil
}

func (s *state) GetTransaction(ctx context.Context, hash hash.SHA256Hash) (transaction Transaction, err error) {
	return s.graph.txByHash(hash)
}

func (s *state) IsPayloadPresent(ctx context.Context, hash hash.SHA256Hash) (present bool, err error) {
	_, ok := s.payloadPerHash[hash]
	return ok, nil
}

func (s *state) IsPresent(ctx context.Context, hash hash.SHA256Hash) (present bool, err error) {
	return s.graph.containsTxHash(hash), nil
}

func (s *state) WritePayload(ctx context.Context, transaction Transaction, payloadHash hash.SHA256Hash, data []byte) error {
	event := Event{
		Type:        PayloadEventType,
		Hash:        transaction.Ref(),
		Retries:     0,
		Transaction: transaction,
		Payload:     data,
	}
	if err := s.saveEvent(event); err != nil {
		return err
	}
	s.payloadPerHash[payloadHash] = string(data)
	s.notify(event)
	return nil
}

func (s *state) ReadPayload(ctx context.Context, hash hash.SHA256Hash) (payload []byte, err error) {
	p, ok := s.payloadPerHash[hash]
	if !ok {
		return nil, ErrPayloadNotFound
	}
	return []byte(p), nil
}

func (s *state) Head(ctx context.Context) (hash.SHA256Hash, error) {
	return s.graph.headTxHash(), nil
}

// Notifier registers receiver under a unique name.
func (s *state) Notifier(name string, receiver ReceiverFn, options ...NotifierOption) (Notifier, error) {
	options = append(options, withCounters(s.eventsNotifyCount, s.eventsFinishedCount))

	n := NewNotifier(name, receiver, options...)

	_, loaded := s.notifiers.LoadOrStore(name, n)
	if loaded {
		return nil, fmt.Errorf("nuts event receiver %q registration denied on duplicate name", name)
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
	s.transactionCount.Add(float64(s.graph.txCount()))

	// resume all notifiers
	var err error
	s.notifiers.Range(func(_, value any) bool {
		err = value.(Notifier).Run()
		return err == nil
	})
	return err
}

// Verify can be used to verify the entire DAG.
// TODO problematic for large sets. Currently not used, see #1216
func (s *state) Verify(ctx context.Context) (err error) {
	s.graph.visitBetweenLC(0, MaxLamportClock, func(tx Transaction) bool {
		err = s.verifyTx(tx)
		return err == nil
	})
	return
}

func (s *state) saveEvent(e Event) error {
	var err error
	s.notifiers.Range(func(_, value any) bool {
		// ⚠️ BUG(pascaldekloe) Notifier Save no longer gets a transaction.
		err = value.(Notifier).Save(nil, e)
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
