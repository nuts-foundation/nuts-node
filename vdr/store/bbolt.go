package store

import (
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"go.etcd.io/bbolt"
)

type documentVersion struct {
	Document did.Document
	Metadata vdr.DocumentMetadata
}

type documentVersionList struct {
	Deactivated bool
	Versions    []hash.SHA256Hash
}

func (entry documentVersionList) Latest() hash.SHA256Hash {
	return entry.Versions[len(entry.Versions)-1]
}

var (
	documentsBucket = []byte("vdrDocuments")
	versionsBucket  = []byte("vdrDocumentVersions")
)

type bboltStore struct {
	db *bbolt.DB
}

// NewBBoltStore returns an instance of a BBolt based VDR store
func NewBBoltStore(db *bbolt.DB) vdr.Store {
	return &bboltStore{db: db}
}

func (store *bboltStore) storeDocument(tx *bbolt.Tx, document did.Document, metadata vdr.DocumentMetadata) error {
	documents, err := tx.CreateBucketIfNotExists(documentsBucket)
	if err != nil {
		return err
	}

	data, err := json.Marshal(documentVersion{
		Document: document,
		Metadata: metadata,
	})
	if err != nil {
		return err
	}

	if err := documents.Put(metadata.Hash.Slice(), data); err != nil {
		return err
	}

	return nil
}

func (store *bboltStore) getDocumentVersion(bucket *bbolt.Bucket, hash hash.SHA256Hash) (*documentVersion, error) {
	data := bucket.Get(hash.Slice())
	if data == nil {
		return nil, nil
	}

	result := &documentVersion{}

	if err := json.Unmarshal(data, result); err != nil {
		return nil, err
	}

	return result, nil
}

// Iterate loops over all the latest versions of the stored DID Documents and applies fn
func (store *bboltStore) Iterate(fn vdr.DocIterator) error {
	return store.db.View(func(tx *bbolt.Tx) error {
		versions := tx.Bucket(versionsBucket)
		if versions == nil {
			return nil
		}

		documents := tx.Bucket(documentsBucket)
		if documents == nil {
			return nil
		}

		if err := versions.ForEach(func(key, data []byte) error {
			versionList := &documentVersionList{}

			if err := json.Unmarshal(data, versionList); err != nil {
				return err
			}

			doc, err := store.getDocumentVersion(documents, versionList.Latest())
			if err != nil {
				return err
			}

			if err := fn(doc.Document, doc.Metadata); err != nil {
				return err
			}

			return nil
		}); err != nil {
			return err
		}

		return nil
	})
}

func (store *bboltStore) filterDocument(doc *documentVersion, metadata *vdr.ResolveMetadata) error {
	// Verify deactivated
	if IsDeactivated(doc.Document) {
		return vdr.ErrDeactivated
	}

	if metadata == nil {
		return nil
	}

	// Filter on hash
	if metadata.Hash != nil && !doc.Metadata.Hash.Equals(*metadata.Hash) {
		return vdr.ErrNotFound
	}

	// Verify creation and update time
	if metadata.ResolveTime != nil {
		resolveTime := *metadata.ResolveTime

		if doc.Metadata.Created.After(resolveTime) {
			return vdr.ErrNotFound
		}

		if doc.Metadata.Updated != nil {
			if doc.Metadata.Updated.After(resolveTime) {
				return vdr.ErrNotFound
			}
		}
	}

	// Verify KeyTransaction
	if metadata.SourceTransaction != nil {
		for i, keyTx := range doc.Metadata.SourceTransactions {
			if keyTx.Equals(*metadata.SourceTransaction) {
				break
			}

			if i == len(doc.Metadata.SourceTransactions)-1 {
				return vdr.ErrNotFound
			}
		}
	}

	return nil
}

// Resolve returns the DID Document for the provided DID
func (store *bboltStore) Resolve(id did.DID, metadata *vdr.ResolveMetadata) (document *did.Document, documentMeta *vdr.DocumentMetadata, txErr error) {
	txErr = store.db.View(func(tx *bbolt.Tx) error {
		documents := tx.Bucket(documentsBucket)
		if documents == nil {
			return vdr.ErrNotFound
		}

		versions := tx.Bucket(versionsBucket)
		if versions == nil {
			return vdr.ErrNotFound
		}

		versionList := &documentVersionList{}

		data := versions.Get([]byte(id.String()))
		if data == nil {
			return vdr.ErrNotFound
		}

		if err := json.Unmarshal(data, versionList); err != nil {
			return err
		}

		data = documents.Get(versionList.Latest().Slice())
		if data == nil {
			return vdr.ErrNotFound
		}

		doc := &documentVersion{}

		if err := json.Unmarshal(data, doc); err != nil {
			return err
		}

		if err := store.filterDocument(doc, metadata); err == nil {
			document = &doc.Document
			documentMeta = &doc.Metadata

			return nil
		}

		return vdr.ErrNotFound
	})

	return
}

// Write writes a DID Document
func (store *bboltStore) Write(document did.Document, metadata vdr.DocumentMetadata) error {
	return store.db.Update(func(tx *bbolt.Tx) error {
		versions, err := tx.CreateBucketIfNotExists(versionsBucket)
		if err != nil {
			return err
		}

		key := []byte(document.ID.String())

		if versions.Get(key) != nil {
			return vdr.ErrDIDAlreadyExists
		}

		// Store versions entry
		data, err := json.Marshal(documentVersionList{
			Deactivated: IsDeactivated(document),
			Versions:    []hash.SHA256Hash{metadata.Hash},
		})
		if err != nil {
			return err
		}

		if err := versions.Put([]byte(document.ID.String()), data); err != nil {
			return err
		}

		// Store the actual document
		return store.storeDocument(tx, document, metadata)
	})
}

// Update replaces the DID document identified by DID with the nextVersion
func (store *bboltStore) Update(id did.DID, current hash.SHA256Hash, next did.Document, metadata *vdr.DocumentMetadata) error {
	return store.db.Update(func(tx *bbolt.Tx) error {
		versions, err := tx.CreateBucketIfNotExists(versionsBucket)
		if err != nil {
			return err
		}

		versionKey := []byte(id.String())

		// Lookup the version information
		data := versions.Get(versionKey)
		if data == nil {
			return vdr.ErrNotFound
		}

		versionList := &documentVersionList{}

		if err := json.Unmarshal(data, versionList); err != nil {
			return err
		}

		if versionList.Deactivated {
			return vdr.ErrDeactivated
		}

		// Verify if the current version hash exists, if so append it
		if versionList.Versions[len(versionList.Versions)-1] != current {
			return vdr.ErrUpdateOnOutdatedData
		}

		// Update version information
		versionList.Versions = append(versionList.Versions, metadata.Hash)
		versionList.Deactivated = versionList.Deactivated || IsDeactivated(next)

		data, err = json.Marshal(versionList)
		if err != nil {
			return err
		}

		if err := versions.Put(versionKey, data); err != nil {
			return err
		}

		// Store the document
		return store.storeDocument(tx, next, *metadata)
	})
}
