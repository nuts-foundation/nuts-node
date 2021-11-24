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
	"github.com/nuts-foundation/nuts-node/crypto"
	"sync"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// NewReplayingDAGPublisher creates a DAG publisher that replays the complete DAG to all subscribers when started.
func NewReplayingDAGPublisher(payloadStore PayloadStore, dag DAG) Publisher {
	publisher := &replayingDAGPublisher{
		subscribers:         map[string]Receiver{},
		resumeAt:            list.New(),
		visitedTransactions: map[hash.SHA256Hash]bool{},
		payloadStore:        payloadStore,
		dag:                 dag,
		publishMux:          &sync.Mutex{},
	}
	dag.RegisterObserver(publisher.TransactionAdded)
	payloadStore.RegisterObserver(publisher.PayloadWritten)
	return publisher
}

type replayingDAGPublisher struct {
	subscribers         map[string]Receiver
	resumeAt            *list.List
	visitedTransactions map[hash.SHA256Hash]bool
	dag                 DAG
	payloadStore        PayloadStore
	docResolver         types.DocResolver
	keyStore            crypto.KeyStore
	publishMux          *sync.Mutex // all calls to publish() must be wrapped in this mutex
}

func (s *replayingDAGPublisher) PayloadWritten(ctx context.Context, _ interface{}) {
	s.publishMux.Lock()
	defer s.publishMux.Unlock()

	s.publish(ctx)
}

func (s *replayingDAGPublisher) TransactionAdded(ctx context.Context, transaction interface{}) {
	s.publishMux.Lock()
	defer s.publishMux.Unlock()

	tx := transaction.(Transaction)
	// Received new transaction, add it to the subscription walker resume list, so it resumes from this transaction
	// when the payload is received.
	s.resumeAt.PushBack(tx.Ref())
	s.publish(ctx)
}

func (s *replayingDAGPublisher) Subscribe(payloadType string, receiver Receiver) {
	oldSubscriber := s.subscribers[payloadType]
	s.subscribers[payloadType] = func(transaction Transaction, payload []byte) error {
		// Chain subscribers in case there's more than 1
		if oldSubscriber != nil {
			if err := oldSubscriber(transaction, payload); err != nil {
				return err
			}
		}
		return receiver(transaction, payload)
	}
}

func (s replayingDAGPublisher) Start() {
	ctx := context.Background()
	s.publishMux.Lock()
	defer s.publishMux.Unlock()

	// since the walker starts at root for an empty hash, no need to find the root first
	s.resumeAt.PushBack(hash.EmptyHash())
	s.publish(ctx)

	log.Logger().Debug("Finished replaying DAG")
}

// publish is called both from PayloadWritten and PublishTransaction
// PayloadWritten will be the correct event during operation, PublishTransaction will be the event at startup
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

func (s *replayingDAGPublisher) handlePrivateTransaction(tx Transaction) error {
	privateKeys := s.keyStore.List()

	for _, keyID := range privateKeys {
		key, err := s.keyStore.Resolve(keyID)
		if err != nil {
			// We could fail here, but it might as well be that this isn't the key we're looking for anyway
			continue
		}

		addr, err := s.keyStore.Decrypt(key, tx.To())
		if err != nil {
			continue
		}

		panic(fmt.Sprintf("got addr: %s", addr))
	}

	// We weren't able to decrypt the 'To' address, so it probably wasn't meant for us
	return nil
}

func (s *replayingDAGPublisher) publishTransaction(ctx context.Context, transaction Transaction) bool {
	// We need to skip transactions with a to addr header as it should be handled by the v2 protocol
	if len(transaction.To()) > 0 {
		if err := s.handlePrivateTransaction(transaction); err != nil {
			log.Logger().Errorf("unable to handle private transaction: (ref=%s) %v", transaction.Ref(), err)
			return false
		}

		return true
	}

	payload, err := s.payloadStore.ReadPayload(ctx, transaction.PayloadHash())
	if err != nil {
		log.Logger().Errorf("Unable to read payload to publish DAG: (ref=%s) %v", transaction.Ref(), err)
		return false
	}

	if payload == nil {
		// We haven't got the payload, break of processing for this branch
		return false
	}

	for _, payloadType := range []string{transaction.PayloadType(), AnyPayloadType} {
		receiver := s.subscribers[payloadType]
		if receiver == nil {
			continue
		}
		if err := receiver(transaction, payload); err != nil {
			log.Logger().Errorf("Transaction subscriber returned an error (ref=%s,type=%s): %v", transaction.Ref(), transaction.PayloadType(), err)
		}
	}

	return true
}
