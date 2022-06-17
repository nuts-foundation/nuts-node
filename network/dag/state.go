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

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
)

const (
	// PageSize specifies the Lamport Clock range over which data is summarized and is used in set reconciliation.
	PageSize = uint32(512)
	// IbltNumBuckets is the number of buckets in the IBLT used in set reconciliation.
	IbltNumBuckets = 1024
)

// State has references to the DAG and the payload store.
type state struct {
	db           stoabs.KVStore
	graph        *bboltDAG
	payloadStore PayloadStore
	txVerifiers  []Verifier
	xorTree      *bboltTree
	ibltTree     *bboltTree
	subscribers  map[string]Subscriber
}

// NewState returns a new State. The State is used as entry point, it's methods will start transactions and will notify observers from within those transactions.
func NewState(db stoabs.KVStore, verifiers ...Verifier) State {
	graph := newBBoltDAG(db)

	payloadStore := NewBBoltPayloadStore(db)
	newState := &state{
		db:           db,
		graph:        graph,
		payloadStore: payloadStore,
		txVerifiers:  verifiers,
		subscribers:  map[string]Subscriber{},
	}

	xorTree := newBBoltTreeStore(db, "xorBucket", tree.New(tree.NewXor(), PageSize))
	ibltTree := newBBoltTreeStore(db, "ibltBucket", tree.New(tree.NewIblt(IbltNumBuckets), PageSize))
	newState.xorTree = xorTree
	newState.ibltTree = ibltTree

	return newState
}

func (s *state) updateTrees(tx stoabs.WriteTx, transaction Transaction) error {
	if err := s.ibltTree.dagObserver(tx, transaction); err != nil {
		return err
	}
	return s.xorTree.dagObserver(tx, transaction)
}

func (s *state) Add(_ context.Context, transaction Transaction, payload []byte) error {
	return s.db.Write(func(tx stoabs.WriteTx) error {
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
				return errors.New("tx.PayloadHash does not match Hash of payload")
			}
			if err := s.writePayload(tx, transaction, payloadHash, payload); err != nil {
				return err
			}
		}
		if err := s.graph.add(tx, transaction); err != nil {
			return err
		}

		// update XOR and IBLT
		if err := s.updateTrees(tx, transaction); err != nil {
			return err
		}

		return s.notifyObservers(tx, "transaction", transaction, payload)
	})
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
		return s.notifyObservers(tx, "payload", transaction, data)
	}
	return err
}

func (s *state) ReadPayload(_ context.Context, hash hash.SHA256Hash) (payload []byte, err error) {
	err = s.db.Read(func(tx stoabs.ReadTx) error {
		payload = s.payloadStore.readPayload(tx, hash)
		return nil
	})
	return
}

func (s *state) Heads(_ context.Context) []hash.SHA256Hash {
	return s.graph.heads()
}

func (s *state) Subscribe(name string, subscriber SubscriberFn, options ...SubscriberOption) (Subscriber, error) {
	if _, exists := s.subscribers[name]; exists {
		return nil, fmt.Errorf("subscriber already exists (name=%s)", name)
	}

	scheduler, err := NewSubscriber(name, subscriber, options...)
	if err != nil {
		return nil, err
	}
	s.subscribers[name] = scheduler

	return scheduler, nil
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

func (s *state) IBLT(reqClock uint32) (tree.Iblt, uint32) {
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
	// TODO: keep track of clock in state
	return s.graph.getHighestClock()
}

func (s *state) Shutdown() error {
	// close all subscribers
	for _, subscriber := range s.subscribers {
		if err := subscriber.Close(); err != nil {
			return err
		}
	}

	return nil
}

func (s *state) Start() error {
	// load trees
	if err := s.db.Read(func(tx stoabs.ReadTx) error {
		if err := s.xorTree.read(tx); err != nil {
			return fmt.Errorf("failed to read xorTree: %w", err)
		}

		if err := s.ibltTree.read(tx); err != nil {
			return fmt.Errorf("failed to read ibltTree: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	if err := s.graph.init(); err != nil {
		return err
	}

	// TODO: remove? This will get slower and slower
	if err := s.Verify(); err != nil {
		return err
	}

	// resume all subscribers
	for _, subscriber := range s.subscribers {
		if err := subscriber.Run(); err != nil {
			return err
		}
	}

	return nil
}

func (s *state) Statistics(ctx context.Context) Statistics {
	return s.graph.statistics(ctx)
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

func (s *state) notifyObservers(tx stoabs.WriteTx, jobType string, transaction Transaction, payload []byte) error {

	job := Job{
		Type:        jobType,
		Hash:        transaction.Ref(),
		Count:       0,
		Transaction: transaction,
		Payload:     payload,
	}

	for _, subscriber := range s.subscribers {
		if err := subscriber.Schedule(tx, job); err != nil {
			return err
		}
	}

	return nil
}

func (s *state) Diagnostics() []core.DiagnosticResult {
	diag := s.graph.diagnostics()
	diag = append(diag, &core.GenericDiagnosticResult{Title: "dag_xor", Outcome: s.xorTree.getRoot().(*tree.Xor).Hash()})
	return diag
}
