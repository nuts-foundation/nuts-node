package dag

import (
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

func (store bboltPayloadStore) IsPresent(payloadHash hash.SHA256Hash) (bool, error) {
	var result bool
	var err error
	err = store.ReadMany(func(reader PayloadReader) error {
		result, err = reader.IsPresent(payloadHash)
		return err
	})
	return result, err
}

func (store bboltPayloadStore) ReadPayload(payloadHash hash.SHA256Hash) ([]byte, error) {
	var result []byte
	var err error
	err = store.ReadMany(func(reader PayloadReader) error {
		result, err = reader.ReadPayload(payloadHash)
		return err
	})
	return result, err
}

func (store bboltPayloadStore) ReadMany(consumer func(reader PayloadReader) error) error {
	return store.db.View(func(tx *bbolt.Tx) error {
		return consumer(newBBoltPayloadReader(tx))
	})
}

func (store bboltPayloadStore) WritePayload(payloadHash hash.SHA256Hash, data []byte) error {
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
		notifyObservers(store.observers, payloadHash)
	}
	return err
}

func newBBoltPayloadReader(tx *bbolt.Tx) PayloadReader {
	return &bboltPayloadReader{payloadsBucket: tx.Bucket([]byte(payloadsBucketName))}
}

type bboltPayloadReader struct {
	payloadsBucket *bbolt.Bucket
}

func (reader bboltPayloadReader) IsPresent(payloadHash hash.SHA256Hash) (bool, error) {
	if reader.payloadsBucket == nil {
		return false, nil
	}
	data := reader.payloadsBucket.Get(payloadHash.Slice())
	return len(data) > 0, nil
}

func (reader bboltPayloadReader) ReadPayload(payloadHash hash.SHA256Hash) ([]byte, error) {
	if reader.payloadsBucket == nil {
		return nil, nil
	}
	return copyBBoltValue(reader.payloadsBucket, payloadHash.Slice()), nil
}
