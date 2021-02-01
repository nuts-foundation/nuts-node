package dag

import (
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"go.etcd.io/bbolt"
)

// payloadsBucket is the name of the Bolt bucket that holds the payloads of the documents.
const payloadsBucket = "payloads"

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
	return isPresent(store.db, payloadsBucket, payloadHash.Slice())
}

func (store bboltPayloadStore) ReadPayload(payloadHash hash.SHA256Hash) ([]byte, error) {
	var result []byte
	err := store.db.View(func(tx *bbolt.Tx) error {
		if payloads := tx.Bucket([]byte(payloadsBucket)); payloads != nil {
			result = payloads.Get(payloadHash.Slice())
		}
		return nil
	})
	return result, err
}

func (store bboltPayloadStore) WritePayload(payloadHash hash.SHA256Hash, data []byte) error {
	err := store.db.Update(func(tx *bbolt.Tx) error {
		payloads, err := tx.CreateBucketIfNotExists([]byte(payloadsBucket))
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
