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
	"github.com/nuts-foundation/nuts-node/network/storage"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"go.etcd.io/bbolt"
)

const (
	// boltDBFileMode holds the Unix file mode the created BBolt database files will have.
	boltDBFileMode = 0600
	// pageSize specifies the Lamport Clock range over which data is summarized and is used in set reconciliation.
	pageSize = uint32(512)
	// ibltNumBuckets is the number of buckets in the IBLT used in set reconciliation.
	ibltNumBuckets = 1024
)

// State has references to the DAG and the payload store.
type state struct {
	db                        *bbolt.DB
	graph                     *bboltDAG
	payloadStore              PayloadStore
	transactionalObservers    []Observer
	nonTransactionalObservers []Observer
	keyResolver               types.KeyResolver
	publisher                 Publisher
	txVerifiers               []Verifier
	xorTree                   *bboltTree
	ibltTree                  *bboltTree
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

	xorTree := newBBoltTreeStore(db, "xorBucket", tree.New(tree.NewXor(), pageSize))
	newState.RegisterObserver(xorTree.dagObserver, true)
	newState.xorTree = xorTree

	ibltTree := newBBoltTreeStore(db, "ibltBucket", tree.New(tree.NewIblt(ibltNumBuckets), pageSize))
	newState.RegisterObserver(ibltTree.dagObserver, true)
	newState.ibltTree = ibltTree

	return newState, nil
}

func (s *state) RegisterObserver(observer Observer, transactional bool) {
	if transactional {
		s.transactionalObservers = append(s.transactionalObservers, observer)
	} else {
		s.nonTransactionalObservers = append(s.nonTransactionalObservers, observer)
	}

}

func (s *state) Add(ctx context.Context, transaction Transaction, payload []byte) error {
	return storage.BBoltTXUpdate(ctx, s.db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
		if err := s.verifyTX(contextWithTX, transaction); err != nil {
			return err
		}
		if payload != nil {
			payloadHash := hash.SHA256Sum(payload)
			if !transaction.PayloadHash().Equals(payloadHash) {
				return errors.New("tx.PayloadHash does not match hash of payload")
			}
			if err := s.payloadStore.WritePayload(contextWithTX, payloadHash, payload); err != nil {
				return err
			}
		}
		if err := s.graph.Add(contextWithTX, transaction); err != nil {
			return err
		}

		s.notifyObservers(contextWithTX, transaction, payload)
		return nil
	})
}

func (s *state) verifyTX(ctx context.Context, tx Transaction) error {
	for _, verifier := range s.txVerifiers {
		if err := verifier(ctx, tx, s); err != nil {
			return fmt.Errorf("transaction verification failed (tx=%s): %w", tx.Ref(), err)
		}
	}
	return nil
}

func (s *state) FindBetween(ctx context.Context, startInclusive time.Time, endExclusive time.Time) ([]Transaction, error) {
	return s.graph.FindBetween(ctx, startInclusive, endExclusive)
}

func (s *state) GetByPayloadHash(ctx context.Context, payloadHash hash.SHA256Hash) ([]Transaction, error) {
	return s.graph.GetByPayloadHash(ctx, payloadHash)
}

func (s *state) GetTransaction(ctx context.Context, hash hash.SHA256Hash) (Transaction, error) {
	return s.graph.Get(ctx, hash)
}

func (s *state) IsPayloadPresent(ctx context.Context, hash hash.SHA256Hash) (bool, error) {
	return s.payloadStore.IsPayloadPresent(ctx, hash)
}

func (s *state) IsPresent(ctx context.Context, hash hash.SHA256Hash) (bool, error) {
	return s.graph.IsPresent(ctx, hash)
}

func (s *state) WritePayload(ctx context.Context, payloadHash hash.SHA256Hash, data []byte) error {
	return storage.BBoltTXUpdate(ctx, s.db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
		err := s.payloadStore.WritePayload(contextWithTX, payloadHash, data)
		if err == nil {
			// ctx passed with bbolt transaction
			s.notifyObservers(contextWithTX, nil, data)
		}
		return err
	})
}

func (s *state) PayloadHashes(ctx context.Context, visitor func(payloadHash hash.SHA256Hash) error) error {
	return s.graph.PayloadHashes(ctx, visitor)
}

func (s *state) ReadManyPayloads(ctx context.Context, consumer func(context.Context, PayloadReader) error) error {
	return s.payloadStore.ReadManyPayloads(ctx, consumer)
}

func (s *state) ReadPayload(ctx context.Context, hash hash.SHA256Hash) ([]byte, error) {
	return s.payloadStore.ReadPayload(ctx, hash)
}

func (s *state) Subscribe(eventType EventType, payloadType string, receiver Receiver) {
	s.publisher.Subscribe(eventType, payloadType, receiver)
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
	// migrate DAG to add Clock values
	if err := s.graph.Migrate(); err != nil {
		return fmt.Errorf("unable to migrate DAG: %w", err)
	}

	// load trees or build if they do not exist yet.
	// can only build after DAG migration added clock values for all transactions and before the publisher starts
	if err := s.xorTree.read(context.Background()); err != nil {
		return fmt.Errorf("failed to read xorTree: %w", err)
	}
	if s.xorTree.isEmpty() {
		err := s.xorTree.buildFromDag(context.Background(), s)
		if err != nil {
			return fmt.Errorf("unable to migrate xorTree: %w", err)
		}
	}

	if err := s.ibltTree.read(context.Background()); err != nil {
		return fmt.Errorf("failed to read ibltTree: %w", err)
	}
	if s.ibltTree.isEmpty() {
		err := s.ibltTree.buildFromDag(context.Background(), s)
		if err != nil {
			return fmt.Errorf("unable to migrate ibltTree: %w", err)
		}
	}

	if err := s.publisher.Start(); err != nil {
		return err
	}

	if err := s.Verify(context.Background()); err != nil {
		return err
	}

	return nil
}

func (s *state) Statistics(ctx context.Context) Statistics {
	return s.graph.Statistics(ctx)
}

func (s *state) Verify(ctx context.Context) error {
	transactions, err := s.FindBetween(ctx, MinTime(), MaxTime())
	if err != nil {
		return err
	}
	for _, tx := range transactions {
		if err := s.verifyTX(ctx, tx); err != nil {
			return err
		}
	}
	return nil
}

func (s *state) Walk(ctx context.Context, visitor Visitor, startAt hash.SHA256Hash) error {
	return s.graph.Walk(ctx, visitor, startAt)
}

// notifyObservers is called from a transactional context. The transactional observers need to be called with the TX context, the other observers after the commit.
func (s *state) notifyObservers(ctx context.Context, transaction Transaction, payload []byte) {
	// apply TX context observers
	for _, observer := range s.transactionalObservers {
		observer(ctx, transaction, payload)
	}

	notifyNonTXObservers := func() {
		for _, observer := range s.nonTransactionalObservers {
			observer(context.Background(), transaction, payload)
		}
	}
	// check if there's an active transaction
	tx, txIsActive := storage.BBoltTX(ctx)
	if txIsActive { // sanity check because there should always be a transaction
		tx.OnCommit(notifyNonTXObservers)
	} else {
		notifyNonTXObservers()
	}
}

func (s *state) Diagnostics() []core.DiagnosticResult {
	diag := s.graph.Diagnostics()
	diag = append(diag, &core.GenericDiagnosticResult{Title: "dag_xor", Outcome: s.xorTree.getRoot().(*tree.Xor).Hash()})
	return diag
}
