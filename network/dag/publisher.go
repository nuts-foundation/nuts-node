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
	"container/list"
	"context"
	"fmt"
	"sync"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/storage"
	"go.etcd.io/bbolt"
)

// NewReplayingDAGPublisher creates a DAG publisher that replays the complete DAG to all subscribers when started.
func NewReplayingDAGPublisher(payloadStore PayloadStore, dag *bboltDAG) Publisher {
	publisher := &replayingDAGPublisher{
		subscribers:         map[EventType]map[string]Receiver{},
		resumeAt:            list.New(),
		visitedTransactions: map[hash.SHA256Hash]bool{},
		dag:                 dag,
		payloadStore:        payloadStore,
		publishMux:          &sync.Mutex{},
	}

	return publisher
}

type replayingDAGPublisher struct {
	subscribers         map[EventType]map[string]Receiver
	resumeAt            *list.List
	visitedTransactions map[hash.SHA256Hash]bool
	dag                 *bboltDAG
	payloadStore        PayloadStore
	publishMux          *sync.Mutex // all calls to publish() must be wrapped in this mutex
}

func (s *replayingDAGPublisher) ConfigureCallbacks(state State) {
	// the publisher only signals the VDR, VCR and transaction state. These need to be called after the bbolt transaction is completed.
	state.RegisterTransactionObserver(func(ctx context.Context, transaction Transaction) error {
		s.publishMux.Lock()
		defer s.publishMux.Unlock()

		return s.transactionAdded(ctx, transaction, nil)
	}, false)

	state.RegisterPayloadObserver(func(transaction Transaction, payload []byte) error {
		s.publishMux.Lock()
		defer s.publishMux.Unlock()

		return s.payloadWritten(context.Background(), transaction, payload)
	}, false)
}

func (s *replayingDAGPublisher) payloadWritten(ctx context.Context, _ Transaction, payload []byte) error {
	payloadHash := hash.EmptyHash()
	if payload != nil {
		// some defensive programming
		payloadHash = hash.SHA256Sum(payload)
	}

	txs, err := s.dag.getByPayloadHash(ctx, payloadHash)
	if err != nil {
		return fmt.Errorf("error while reading TXs by PayloadHash (payloadHash=%s): %v", payloadHash.String(), err)
	}
	if len(txs) == 0 {
		// No transaction found for this payload hash.
		// This happens when a transaction was created by the local node, which first writes payload, then adds TX to the DAG.
		// But when the actual TX is added and transactionAdded() is called, it will still resume publishing from that TX,
		// so all required events will still be emitted.
		return nil
	}

	// make sure publisher resumes at these points
	for _, tx := range txs {
		if !s.visitedTransactions[tx.Ref()] {
			s.resumeAt.PushBack(tx.Ref())
		}
	}

	return s.publish(ctx)
}

// transactionAdded is called by the DAG when a new transaction is added.
func (s *replayingDAGPublisher) transactionAdded(ctx context.Context, transaction Transaction, _ []byte) error {
	tx := transaction.(Transaction)

	// The transaction itself has already been validated by the network layer. So the dependencies of this TX are already processed in the VDR.
	s.emitEvent(TransactionAddedEvent, tx, nil)

	// Received new transaction, add it to the subscription walker resume list, so it resumes from this transaction
	// when the payload is received.
	s.resumeAt.PushBack(tx.Ref())
	return s.publish(ctx)
}

func (s *replayingDAGPublisher) Subscribe(eventType EventType, payloadType string, receiver Receiver) {
	if _, ok := s.subscribers[eventType]; !ok {
		s.subscribers[eventType] = make(map[string]Receiver, 0)
	}
	oldSubscriber := s.subscribers[eventType][payloadType]
	s.subscribers[eventType][payloadType] = func(transaction Transaction, payload []byte) error {
		// Chain subscribers in case there's more than 1
		if oldSubscriber != nil {
			if err := oldSubscriber(transaction, payload); err != nil {
				return err
			}
		}
		return receiver(transaction, payload)
	}
}

func (s *replayingDAGPublisher) Start() error {
	return s.replay()
}

// publish is called both from payloadWritten and transactionAdded. Only when both are satisfied (transaction is present and payload as well), the transaction is published.
// payloadWritten will be the correct event during operation, transactionAdded will be the event at startup
func (s *replayingDAGPublisher) publish(ctx context.Context) error {
	front := s.resumeAt.Front()
	if front == nil {
		return nil
	}

	currentRef := front.Value.(hash.SHA256Hash)
	return storage.BBoltTXView(ctx, s.dag.db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
		return s.dag.walk(tx, func(tx *bbolt.Tx, transaction Transaction) bool {
			outcome := s.publishTransaction(tx, transaction)
			if outcome {
				remove(s.resumeAt, transaction.Ref())
			}
			return outcome
		}, currentRef)
	})
}

func remove(l *list.List, ref hash.SHA256Hash) {
	current := l.Front()

	for {
		if current == nil {
			return
		}
		if current.Value.(hash.SHA256Hash).Equals(ref) {
			l.Remove(current)
		}
		current = current.Next()
	}
}

func (s *replayingDAGPublisher) publishTransaction(tx *bbolt.Tx, transaction Transaction) bool {
	payload := s.payloadStore.readPayload(tx, transaction.PayloadHash())

	if payload == nil {
		if isBlockingTransaction(transaction) {
			// public TX but without payload, TX processing only. Wait for payload
			return false
		}
	} else {
		if !s.visitedTransactions[transaction.Ref()] {
			s.emitEvent(TransactionPayloadAddedEvent, transaction, payload)
			// prevent DID doc updates to come back and haunt us. DID doc updates may reuse a payload hash already seen earlier.
			// payloadWritten will then also find the old TX
			s.visitedTransactions[transaction.Ref()] = true
		}
	}

	return true
}

func (s *replayingDAGPublisher) emitEvent(eventType EventType, transaction Transaction, payload []byte) {
	for _, payloadType := range []string{transaction.PayloadType(), AnyPayloadType} {
		subs := s.subscribers[eventType]
		if subs == nil {
			continue
		}
		receiver := subs[payloadType]
		if receiver == nil {
			continue
		}
		if err := receiver(transaction, payload); err != nil {
			log.Logger().Errorf("Transaction subscriber returned an error (ref=%s,type=%s): %v", transaction.Ref(), transaction.PayloadType(), err)
		}
	}
}

// replay uses transactionAdded and payloadWritten to emit events. Both of these call publishTransaction which may cause events to be emitted more than once.
func (s *replayingDAGPublisher) replay() error {
	log.Logger().Debug("Replaying DAG...")
	s.publishMux.Lock()
	defer s.publishMux.Unlock()

	err := storage.BBoltTXView(context.Background(), s.dag.db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
		return s.dag.walk(tx, func(tx *bbolt.Tx, transaction Transaction) bool {
			s.emitEvent(TransactionAddedEvent, transaction, nil)
			payload := s.payloadStore.readPayload(tx, transaction.PayloadHash())
			if payload == nil {
				if isBlockingTransaction(transaction) {
					// public TX but without payload, TX processing only. Wait for payload.
					// This is probably a DID Document Create/Update. We need the payload before we process any depending payloads
					s.resumeAt.PushBack(transaction.Ref())
					return false
				}
			} else {
				s.emitEvent(TransactionPayloadAddedEvent, transaction, payload)
				// prevent DID doc updates to come back and haunt us. DID doc updates may reuse a payload hash already seen earlier.
				// payloadWritten will then also find the old TX
				s.visitedTransactions[transaction.Ref()] = true
			}
			return true
		}, hash.EmptyHash())
	})
	if err != nil {
		return err
	}
	log.Logger().Debug("Finished replaying DAG")
	return nil
}

// isBlockingTransaction returns true if for the given transaction the payload must have been processed before continuing to the next tx.
func isBlockingTransaction(tx Transaction) bool {
	return tx.PayloadType() == "application/did+json"
}
