package dag

import (
	"context"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"go.etcd.io/bbolt"
)

// payloadsBucketName is the name of the Bolt bucket that holds the payloads of the transactions.
const payloadsBucketName = "payloads"

// NewBBoltPayloadStore creates a etcd/bbolt backed payload store using the given database.
func NewBBoltPayloadStore(db *bbolt.DB) PayloadStore {
	return &bboltPayloadStore{db: db, observers: []Observer{}}
}

type bboltPayloadStore struct {
	db        *bbolt.DB
	observers []Observer
}

func (store *bboltPayloadStore) RegisterObserver(observer Observer) {
	store.observers = append(store.observers, observer)
}

func (store bboltPayloadStore) IsPresent(ctx context.Context, payloadHash hash.SHA256Hash) (bool, error) {
	var result bool
	var err error
	err = store.ReadMany(ctx, func(ctx context.Context, reader PayloadReader) error {
		result, err = reader.IsPresent(ctx, payloadHash)
		return err
	})
	return result, err
}

func (store bboltPayloadStore) ReadPayload(ctx context.Context, payloadHash hash.SHA256Hash) ([]byte, error) {
	var result []byte
	var err error
	err = store.ReadMany(ctx, func(ctx context.Context, reader PayloadReader) error {
		result, err = reader.ReadPayload(ctx, payloadHash)
		return err
	})
	return result, err
}

func (store bboltPayloadStore) ReadMany(ctx context.Context, consumer func(ctx context.Context, reader PayloadReader) error) error {
	return bboltTXView(ctx, store.db, func(ctx context.Context, tx *bbolt.Tx) error {
		return consumer(ctx, &bboltPayloadReader{payloadsBucket: tx.Bucket([]byte(payloadsBucketName))})
	})
}

func (store bboltPayloadStore) WritePayload(ctx context.Context, payloadHash hash.SHA256Hash, data []byte) error {
	err := store.db.Update(func(tx *bbolt.Tx) error {
		payloads, err := tx.CreateBucketIfNotExists([]byte(payloadsBucketName))
		if err != nil {
			return err
		}
		if err := payloads.Put(payloadHash.Slice(), data); err != nil {
			return err
		}
		return nil
	})
	if err == nil {
		notifyObservers(ctx, store.observers, payloadHash)
	}
	return err
}

type bboltPayloadReader struct {
	payloadsBucket *bbolt.Bucket
}

func (reader bboltPayloadReader) IsPresent(_ context.Context, payloadHash hash.SHA256Hash) (bool, error) {
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
	return copyBBoltValue(reader.payloadsBucket, payloadHash.Slice()), nil
}
