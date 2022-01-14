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
	"time"

	"github.com/nats-io/nats.go"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network/log"
)

// NewReplayingDAGPublisher creates a DAG publisher that replays the complete DAG to all subscribers when started.
func NewReplayingDAGPublisher(eventManager events.Event, payloadStore PayloadStore, dag DAG) Publisher {
	publisher := &replayingDAGPublisher{
		subscribers:         map[EventType]map[string]Receiver{},
		resumeAt:            list.New(),
		visitedTransactions: map[hash.SHA256Hash]bool{},
		dag:                 dag,
		payloadStore:        payloadStore,
		publishMux:          &sync.Mutex{},
		eventManager:        eventManager,
	}

	return publisher
}

type replayingDAGPublisher struct {
	subscribers         map[EventType]map[string]Receiver
	resumeAt            *list.List
	visitedTransactions map[hash.SHA256Hash]bool
	dag                 DAG
	payloadStore        PayloadStore
	eventManager        events.Event
	privateTxCtx        events.JetStreamContext
	publishMux          *sync.Mutex // all calls to publish() must be wrapped in this mutex
}

// payloadWritten is called by the PayloadStore when a transaction payload is written.
func (s *replayingDAGPublisher) payloadWritten(ctx context.Context, _ interface{}) {
	s.publish(ctx)
}

// transactionAdded is called by the DAG when a new transaction is added.
func (s *replayingDAGPublisher) transactionAdded(ctx context.Context, transaction interface{}) {
	tx := transaction.(Transaction)

	s.emitEvent(TransactionAddedEvent, tx, nil)

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

	var err error
	_, s.privateTxCtx, err = s.eventManager.Pool().Acquire(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire a connection for events: %w", err)
	}

	_, err = s.privateTxCtx.AddStream(&nats.StreamConfig{
		Name:     events.PrivateTransactionsStream,
		Subjects: []string{events.PrivateTransactionsSubject},
	})
	if err != nil {
		return fmt.Errorf("failed to setup NATS stream: %w", err)
	}

	s.dag.RegisterObserver(func(ctx context.Context, subject interface{}) {
		s.publishMux.Lock()
		defer s.publishMux.Unlock()
		s.transactionAdded(ctx, subject)
	})
	s.payloadStore.RegisterObserver(func(ctx context.Context, subject interface{}) {
		s.publishMux.Lock()
		defer s.publishMux.Unlock()
		s.payloadWritten(ctx, subject)
	})

	return s.replay()
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

func (s *replayingDAGPublisher) handlePrivateTransaction(tx Transaction) {
	_, err := s.privateTxCtx.PublishAsync(events.PrivateTransactionsSubject, tx.Data())

	if err != nil {
		log.Logger().Errorf("unable to handle private transaction: (ref=%s) %v", tx.Ref(), err)
	}
}

func (s *replayingDAGPublisher) publishTransaction(ctx context.Context, transaction Transaction) bool {
	payload, err := s.payloadStore.ReadPayload(ctx, transaction.PayloadHash())
	if err != nil {
		log.Logger().Errorf("Unable to read payload to publish DAG: (ref=%s) %v", transaction.Ref(), err)
		return false
	}

	if payload == nil {
		// Handle private transactions via V2 protocol
		if len(transaction.PAL()) > 0 {
			s.handlePrivateTransaction(transaction)
		}

		// We haven't got the payload, break of processing for this branch
		return false
	}

	s.emitEvent(TransactionPayloadAddedEvent, transaction, payload)

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

func (s *replayingDAGPublisher) replay() error {
	log.Logger().Debug("Replaying DAG...")
	s.publishMux.Lock()
	defer s.publishMux.Unlock()

	err := s.dag.Walk(context.Background(), func(ctx context.Context, tx Transaction) bool {
		s.transactionAdded(ctx, tx)
		payload, err := s.payloadStore.ReadPayload(ctx, tx.PayloadHash())
		if err != nil {
			log.Logger().Errorf("Error reading payload (tx=%s): %v", tx.Ref(), err)
		}
		if payload == nil {
			return false
		}
		s.payloadWritten(ctx, tx)
		return true
	}, hash.EmptyHash())
	if err != nil {
		return err
	}
	log.Logger().Debug("Finished replaying DAG")
	return nil
}
