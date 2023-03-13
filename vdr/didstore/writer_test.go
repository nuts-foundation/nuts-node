/*
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

package didstore

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_writeEventList(t *testing.T) {
	store := NewTestStore(t)

	t.Run("ok", func(t *testing.T) {
		el := eventList{Events: []event{{PayloadHash: hash.RandomHash()}}}
		err := store.db.Write(context.Background(), func(tx stoabs.WriteTx) error {
			return writeEventList(tx, el, testDID)
		})
		require.NoError(t, err)

		err = store.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
			eventShelf := tx.GetShelfReader(eventShelf)
			elBytes, _ := eventShelf.Get(stoabs.BytesKey(testDID.String()))
			elResult := eventList{}
			_ = json.Unmarshal(elBytes, &elResult)

			assert.Equal(t, el, elResult)

			return nil
		})
		require.NoError(t, err)
	})
}

func Test_writeDocument(t *testing.T) {
	document := did.Document{ID: testDID}
	transaction := newTestTransaction(document)
	store := NewTestStore(t)

	err := store.db.Write(context.Background(), func(tx stoabs.WriteTx) error {
		return writeDocument(tx, document, transaction)
	})
	require.NoError(t, err)

	t.Run("documentShelf", func(t *testing.T) {
		err = store.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
			documentShelf := tx.GetShelfReader(documentShelf)
			docBytes, _ := documentShelf.Get(stoabs.HashKey(transaction.PayloadHash))
			docResult := did.Document{}
			_ = json.Unmarshal(docBytes, &docResult)

			assert.Equal(t, document, docResult)

			return nil
		})
		require.NoError(t, err)
	})

	t.Run("transactionIndexShelf", func(t *testing.T) {
		err = store.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
			transactionIndexShelf := tx.GetShelfReader(transactionIndexShelf)
			txIndexBytes, _ := transactionIndexShelf.Get(stoabs.HashKey(transaction.Ref))

			// the payloadHash is written
			assert.Equal(t, transaction.PayloadHash.Slice(), txIndexBytes)

			return nil
		})
		require.NoError(t, err)
	})
}

func Test_writeLatest(t *testing.T) {
	store := NewTestStore(t)
	metadata := documentMetadata{
		Version: 1,
	}
	err := store.db.Write(context.Background(), func(tx stoabs.WriteTx) error {
		return writeLatest(tx, testDID, metadata)
	})
	require.NoError(t, err)

	err = store.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
		latestShelf := tx.GetShelfReader(latestShelf)
		metaRefBytes, _ := latestShelf.Get(stoabs.BytesKey(testDID.String()))

		// a single 0 is written
		assert.Equal(t, fmt.Sprintf("%s%d", testDID.String(), 1), string(metaRefBytes))

		return nil
	})
	require.NoError(t, err)
}

func Test_incrementDocumentCount(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		store := NewTestStore(t)
		err := store.db.Write(context.Background(), func(tx stoabs.WriteTx) error {
			return incrementDocumentCount(tx)
		})
		require.NoError(t, err)

		err = store.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
			statsShelf := tx.GetShelfReader(statsShelf)
			countBytes, _ := statsShelf.Get(stoabs.BytesKey(documentCountKey))

			// a single 0 is written
			assert.Equal(t, []byte{0, 0, 0, 1}, countBytes)

			return nil
		})
		require.NoError(t, err)
	})
	t.Run("plus one", func(t *testing.T) {
		store := NewTestStore(t)
		err := store.db.Write(context.Background(), func(tx stoabs.WriteTx) error {
			incrementDocumentCount(tx)
			return incrementDocumentCount(tx)
		})
		require.NoError(t, err)

		err = store.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
			statsShelf := tx.GetShelfReader(statsShelf)
			countBytes, _ := statsShelf.Get(stoabs.BytesKey(documentCountKey))

			// a single 0 is written
			assert.Equal(t, []byte{0, 0, 0, 2}, countBytes)

			return nil
		})
		require.NoError(t, err)
	})

}

func Test_applyDocument(t *testing.T) {
	type test struct {
		name         string
		currentDoc   *did.Document
		currentMeta  *documentMetadata
		newDoc       did.Document
		newMeta      documentMetadata
		expectedMeta documentMetadata
	}

	time0 := time.Now().Add(-2 * time.Second)
	doc0 := did.Document{ID: testDID, Controller: []did.DID{testDID}}
	tx0 := newTestTransaction(doc0)
	meta0 := documentMetadata{
		Version:            0,
		Created:            time0,
		Updated:            time0,
		Hash:               tx0.PayloadHash,
		SourceTransactions: []hash.SHA256Hash{tx0.Ref},
		Deactivated:        false,
	}
	time1 := time.Now().Add(-1 * time.Second)
	doc1 := did.Document{ID: testDID, Controller: []did.DID{testDID}, Service: []did.Service{{ID: ssi.MustParseURI("test")}}}
	tx1 := newTestTransaction(doc1)
	meta1 := documentMetadata{
		Version:            0,
		Created:            time1,
		Updated:            time1,
		Hash:               tx1.PayloadHash,
		SourceTransactions: []hash.SHA256Hash{tx1.Ref},
		Deactivated:        false,
	}

	deactivatedDoc := did.Document{ID: testDID}
	deactivatedTx := newTestTransaction(deactivatedDoc)
	//deactivatedHash := deactivatedTx.PayloadHash()
	deactivatedMeta := documentMetadata{
		Version:            0,
		Created:            time1,
		Updated:            time1,
		Hash:               deactivatedTx.PayloadHash,
		SourceTransactions: []hash.SHA256Hash{deactivatedTx.Ref},
		Deactivated:        true,
	}
	tests := []test{
		{
			"apply newly created document",
			nil,
			nil,
			doc0,
			meta0,
			meta0,
		},
		{
			"apply an update",
			&doc0,
			&meta0,
			doc1,
			meta1.copy(func(m *documentMetadata) { m.PreviousTransaction = meta0.SourceTransactions }),
			meta1.copy(func(m *documentMetadata) {
				m.Created = time0
				m.Version = 1
				m.PreviousTransaction = meta0.SourceTransactions
				m.PreviousHash = &meta0.Hash
			}),
		},
		{
			"deactivate",
			&doc0,
			&meta0,
			deactivatedDoc,
			deactivatedMeta.copy(func(m *documentMetadata) { m.PreviousTransaction = meta0.SourceTransactions }),
			deactivatedMeta.copy(func(m *documentMetadata) {
				m.Created = time0
				m.Version = 1
				m.PreviousTransaction = meta0.SourceTransactions
				m.PreviousHash = &meta0.Hash
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, resultMeta, err := applyDocument(nil, test.currentMeta, test.newDoc, test.newMeta)
			require.NoError(t, err)

			assert.Equal(t, test.expectedMeta.Version, resultMeta.Version)
			assert.Equal(t, test.expectedMeta.Created, resultMeta.Created)
			assert.Equal(t, test.expectedMeta.Updated, resultMeta.Updated)
			assert.Equal(t, test.expectedMeta.Deactivated, resultMeta.Deactivated)
			assert.Equal(t, test.expectedMeta.Hash, resultMeta.Hash)
			assert.Equal(t, test.expectedMeta.PreviousTransaction, resultMeta.PreviousTransaction)
			assert.Equal(t, test.expectedMeta.SourceTransactions, resultMeta.SourceTransactions)
			if test.expectedMeta.PreviousHash != nil {
				require.NotNil(t, resultMeta.PreviousHash)
				assert.Equal(t, *test.expectedMeta.PreviousHash, *resultMeta.PreviousHash)
			}
		})
	}

	t.Run("apply parallel update", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockTX := stoabs.NewMockReadTx(ctrl)
		mockTXShelf := stoabs.NewMockReader(ctrl)
		mockDocShelf := stoabs.NewMockReader(ctrl)
		mockTX.EXPECT().GetShelfReader(transactionIndexShelf).Return(mockTXShelf)
		mockTX.EXPECT().GetShelfReader(documentShelf).Return(mockDocShelf)
		mockTXShelf.EXPECT().Get(gomock.Any()).Return(meta0.Hash.Slice(), nil)
		docBytes, _ := json.Marshal(doc0)
		mockDocShelf.EXPECT().Get(stoabs.HashKey(meta0.Hash)).Return(docBytes, nil)
		expectedMeta := meta1.copy(func(m *documentMetadata) {
			m.Created = time0
			m.Version = 1
			m.SourceTransactions = []hash.SHA256Hash{tx1.Ref, tx0.Ref}
			m.PreviousHash = &meta0.Hash
		})

		_, resultMeta, err := applyDocument(mockTX, &meta0, doc1, meta1)
		require.NoError(t, err)

		assert.Equal(t, expectedMeta.Version, resultMeta.Version)
		assert.Equal(t, expectedMeta.Created, resultMeta.Created)
		assert.Equal(t, expectedMeta.Updated, resultMeta.Updated)
		assert.Equal(t, expectedMeta.Deactivated, resultMeta.Deactivated)
		assert.Equal(t, expectedMeta.Hash, resultMeta.Hash)
		assert.Equal(t, expectedMeta.PreviousTransaction, resultMeta.PreviousTransaction)
		assert.Equal(t, expectedMeta.SourceTransactions, resultMeta.SourceTransactions)
		require.NotNil(t, resultMeta.PreviousHash)
		assert.Equal(t, *expectedMeta.PreviousHash, *resultMeta.PreviousHash)
	})
}

func (md documentMetadata) copy(f func(m *documentMetadata)) documentMetadata {
	cpy := md
	f(&cpy)
	return cpy
}
