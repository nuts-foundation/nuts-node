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
	"bytes"
	"context"
	"errors"
	"os"
	"path"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/storage"
	"go.etcd.io/bbolt"
)

// payloadsBucketName is the name of the Bolt bucket that holds the payloads of the transactions.
const payloadsBucketName = "payloads"

// privatePayloadsBucketName is the name of the Bolt bucket that holds the payloads of the transactions.
const privatePayloadsBucketName = "private_payloads"

// privateMagicBytes define the byte sequence that identifies a private payload (`PRIV` in ASCII).
var privateMagicBytes = [...]byte{0x50, 0x52, 0x49, 0x56}

type payloadHeader struct {
	Private bool
	StoreID hash.SHA256Hash
	Data    []byte
}

func (header payloadHeader) encode() []byte {
	if header.Private {
		return append(privateMagicBytes[:], header.StoreID[:]...)
	}

	return header.Data
}

func decodeHeader(data []byte) payloadHeader {
	if bytes.HasPrefix(data, privateMagicBytes[:]) {
		offset := len(privateMagicBytes)
		header := payloadHeader{Private: true}

		copy(header.StoreID[:], data[offset:offset+hash.SHA256HashSize])

		return header
	}

	return payloadHeader{Data: data}
}

// NewBBoltPayloadStore creates an etcd/bbolt backed payload store using the given database.
func NewBBoltPayloadStore(db *bbolt.DB) PayloadStore {
	return &bboltPayloadStore{db: db, privatePool: NewBBoltPool()}
}

type bboltPayloadStore struct {
	db          *bbolt.DB
	privatePool *BBoltPool
}

func (store bboltPayloadStore) IsPayloadPresent(ctx context.Context, payloadHash hash.SHA256Hash) (bool, error) {
	var result bool
	var err error
	err = store.ReadManyPayloads(ctx, func(ctx context.Context, reader PayloadReader) error {
		result, err = reader.IsPayloadPresent(ctx, payloadHash)
		return err
	})
	return result, err
}

func (store bboltPayloadStore) ReadPayload(ctx context.Context, payloadHash hash.SHA256Hash) (result []byte, err error) {
	err = store.ReadManyPayloads(ctx, func(ctx context.Context, reader PayloadReader) error {
		result, err = reader.ReadPayload(ctx, payloadHash)
		return err
	})
	return result, err
}

func (store bboltPayloadStore) ReadManyPayloads(ctx context.Context, consumer func(ctx context.Context, reader PayloadReader) error) error {
	return storage.BBoltTXView(ctx, store.db, func(contextWithTX context.Context, tx *bbolt.Tx) error {
		return consumer(contextWithTX, &bboltPayloadReader{payloadsBucket: tx.Bucket([]byte(payloadsBucketName))})
	})
}

func (store bboltPayloadStore) WritePayload(ctx context.Context, payloadHash hash.SHA256Hash, storeID *hash.SHA256Hash, data []byte) error {
	return storage.BBoltTXUpdate(ctx, store.db, func(_ context.Context, tx *bbolt.Tx) error {
		payloads, err := tx.CreateBucketIfNotExists([]byte(payloadsBucketName))
		if err != nil {
			return err
		}

		header := payloadHeader{}

		if storeID == nil {
			header.Data = data
		} else {
			header.Private = true
			header.StoreID = *storeID
		}

		if err := payloads.Put(payloadHash.Slice(), header.encode()); err != nil {
			return err
		}

		if !header.Private {
			return nil
		}

		// If this is a private transaction we still need to sture the actual data in its own store
		privateStore, ok := store.privatePool.Get(*storeID)
		if !ok {
			privateStore, err = store.createPrivateStore(*storeID)
			if err != nil {
				return err
			}
		}

		return privateStore.Update(func(tx *bbolt.Tx) error {
			return tx.Bucket([]byte(payloadsBucketName)).Put(payloadHash.Slice(), data)
		})
	})
}

func (store bboltPayloadStore) createPrivateStore(storeID hash.SHA256Hash) (*bbolt.DB, error) {
	dirname := path.Join(path.Base(store.db.Path()), "private")

	if _, err := os.Stat(dirname); os.IsNotExist(err) {
		if err := os.MkdirAll(dirname, 0700); err != nil {
			return nil, err
		}
	}

	filename := path.Join(dirname, storeID.String())

	db, err := bbolt.Open(filename, 0600, nil)
	if err != nil {
		return nil, err
	}

	if err := store.privatePool.Add(storeID, db); err != nil {
		return nil, err
	}

	return db, nil
}

type bboltPayloadReader struct {
	payloadsBucket *bbolt.Bucket
}

func (reader bboltPayloadReader) IsPayloadPresent(_ context.Context, payloadHash hash.SHA256Hash) (bool, error) {
	if reader.payloadsBucket == nil {
		return false, nil
	}
	data := reader.payloadsBucket.Get(payloadHash.Slice())
	return len(data) > 0, nil
}

func (reader bboltPayloadReader) ReadPayload(_ context.Context, payloadHash hash.SHA256Hash) ([]byte, error) {
	if reader.payloadsBucket == nil {
		return nil, nil
	}

	value := reader.payloadsBucket.Get(payloadHash.Slice())
	if value == nil {
		return nil, nil
	}

	header := decodeHeader(value)

	if header.Private {
		return nil, errors.New("not supported")
	}

	return copyBBoltValue(header.Data), nil
}
