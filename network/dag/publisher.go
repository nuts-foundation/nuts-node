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
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
)

// NewReplayingDAGPublisher creates a DAG publisher that replays the complete DAG to all subscribers when started.
func NewReplayingDAGPublisher(payloadStore PayloadStore, dag DAG) Publisher {
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
	dag                 DAG
	payloadStore        PayloadStore
	publishMux          *sync.Mutex // all calls to publish() must be wrapped in this mutex
}

func (s *replayingDAGPublisher) payloadWritten(ctx context.Context, payloadHash interface{}) {
	s.publishMux.Lock()
	defer s.publishMux.Unlock()

	h := payloadHash.(hash.SHA256Hash)
	txs, err := s.dag.GetByPayloadHash(ctx, h)

	if err != nil || len(txs) == 0 {
		log.Logger().Errorf("failed to retrieve transaction by payloadHash (%s)", h.String())
		return
	}

	if txs[0].PayloadType() != "application/did+json" {
		// required to signal VCR/VDR for VCs
		if !s.visitedTransactions[txs[0].Ref()] {
			if outcome := s.publishTransaction(ctx, txs[0]); outcome {
				// Mark this node as visited
				s.visitedTransactions[txs[0].Ref()] = true
			}
		}
		return
	}

	// All did doc txs require payload.
	s.publish(ctx)
}

func (s *replayingDAGPublisher) transactionAdded(ctx context.Context, transaction interface{}) {
	s.publishMux.Lock()
	defer s.publishMux.Unlock()

	tx := transaction.(Transaction)
	// Received new transaction, add it to the subscription walker resume list, so it resumes from this transaction
	// when the payload is received.
	s.resumeAt.PushBack(tx.Ref())
	s.publish(ctx)
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	s.dag.RegisterObserver(s.transactionAdded)
	s.payloadStore.RegisterObserver(s.payloadWritten)

	ctx = context.Background()
	s.publishMux.Lock()
	defer s.publishMux.Unlock()

	// since the walker starts at root for an empty hash, no need to find the root first
	s.resumeAt.PushBack(hash.EmptyHash())
	s.publish(ctx)

	log.Logger().Debug("Finished replaying DAG")
	return nil
}

// publish is called both from payloadWritten and transactionAdded. Only when both are satified (transaction is present and payload as well), the transaction is published.
// payloadWritten will be the correct event during operation, transactionAdded will be the event at startup
func (s *replayingDAGPublisher) publish(ctx context.Context) {
	front := s.resumeAt.Front()
	if front == nil {
		return
	}

	currentRef := front.Value.(hash.SHA256Hash)
	err := s.dag.Walk(ctx, func(ctx context.Context, transaction Transaction) bool {
		outcome := true
		txRef := transaction.Ref()
		// visit once
		if !s.visitedTransactions[txRef] {
			if outcome = s.publishTransaction(ctx, transaction); outcome {
				// Mark this node as visited
				s.visitedTransactions[txRef] = true
			}
		}
		if outcome && currentRef.Equals(txRef) {
			s.resumeAt.Remove(front)
		}
		return outcome
	}, currentRef)
	if err != nil {
		log.Logger().Errorf("Unable to publish DAG: %v", err)
	}
}

func (s *replayingDAGPublisher) publishTransaction(ctx context.Context, transaction Transaction) bool {
	payload, err := s.payloadStore.ReadPayload(ctx, transaction.PayloadHash())
	if err != nil {
		log.Logger().Errorf("Unable to read payload to publish DAG: (ref=%s) %v", transaction.Ref(), err)
		return false
	}

	if transaction.PayloadType() == "application/did+json" {
		if payload == nil {
			// public TX but without payload, TX processing only. Wait for payload
			return false
		}
	}

	// TODO: Now calls TransactionAddedEvent and TransactionPayloadAddedEvent after checken whether the payload is present.
	//       This will need to be changed: TransactionAddedEvent must be called regardless whether the payload is present or not (e.g. top of this function).
	//       However, when doing that at this moment, TransactionAddedEvent might be published multiple times for transactions which payload is not present the first time.
	//       This is generally the case during operation when new transactions are received over the network.
	//       Since not all subscribers are guaranteed to be idempotent at this time, they might break if we introduce it at this moment in time.
	//       So after all subscribers are made idempotent, TransactionAddedEvent must be published regardless of the payload is present or not.
	//       This is to accommodate syncing DAGs even when receiving a TX with a detached payload, or a private TX not meant for the local node.
	for eventType := range s.subscribers {
		for _, payloadType := range []string{transaction.PayloadType(), AnyPayloadType} {
			receiver := s.subscribers[eventType][payloadType]
			if receiver == nil {
				continue
			}
			if err := receiver(transaction, payload); err != nil {
				log.Logger().Errorf("Transaction subscriber returned an error (ref=%s,type=%s): %v", transaction.Ref(), transaction.PayloadType(), err)
			}
		}
	}

	return true
}
