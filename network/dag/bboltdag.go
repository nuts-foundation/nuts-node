/*
 * Copyright (C) 2021. Nuts community
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
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	log "github.com/nuts-foundation/nuts-node/network/log"
	"go.etcd.io/bbolt"
)

// payloadsBucket is the name of the Bolt bucket that holds the payloads of the documents.
const payloadsBucket = "payloads"

// documentsBucket is the name of the Bolt bucket that holds the actual documents as JSON.
const documentsBucket = "documents"

// missingDocumentsBucket is the name of the Bolt bucket that holds the references of the documents we're having prevs
// to, but are missing (and will be added later, hopefully).
const missingDocumentsBucket = "missingdocuments"

// payloadIndexBucket is the name of the Bolt bucket that holds the a reverse reference from payload hash back to documents.
// The value ([]byte) should be split in chunks of HashSize where each entry is a document reference that refers to
// the payload.
const payloadIndexBucket = "payloadIndex"

// nextsBucket is the name of the Bolt bucket that holds the forward document references (a.k.a. "nexts") as document
// refs. The value ([]byte) should be split in chunks of HashSize where each entry is a forward reference (next).
const nextsBucket = "nexts"

// rootDocumentKey is the name of the bucket entry that holds the refs of the root documents.
const rootsDocumentKey = "roots"

// headsBucket contains the name of the bucket the holds the heads.
const headsBucket = "heads"

// boltDBFileMode holds the Unix file mode the created BBolt database files will have.
const boltDBFileMode = 0600

type bboltDAG struct {
	db          *bbolt.DB
	subscribers map[string]Receiver
}

type headsStatistic struct {
	// SHA256Hash is the last consistency hash.
	heads []hash.SHA256Hash
}

func (d headsStatistic) Name() string {
	return "[DAG] Heads"
}

func (d headsStatistic) String() string {
	return fmt.Sprintf("%v", d.heads)
}

type numberOfDocumentsStatistic struct {
	numberOfDocuments int
}

func (d numberOfDocumentsStatistic) Name() string {
	return "[DAG] Number of documents"
}

func (d numberOfDocumentsStatistic) String() string {
	return fmt.Sprintf("%d", d.numberOfDocuments)
}

type dataSizeStatistic struct {
	sizeInBytes int
}

func (d dataSizeStatistic) Name() string {
	return "[DAG] Stored document size (bytes)"
}

func (d dataSizeStatistic) String() string {
	return fmt.Sprintf("%d", d.sizeInBytes)
}

// NewBBoltDAG creates a etcd/bbolt backed DAG using the given database file path. If the file doesn't exist, it's created.
// The parent directory of the path must exist, otherwise an error could be returned. If the file can't be created or
// read, an error is returned as well.
func NewBBoltDAG(path string) (DAG, PayloadStore, error) {
	db, err := bbolt.Open(path, boltDBFileMode, bbolt.DefaultOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create bbolt DAG: %w", err)
	}
	instance := &bboltDAG{
		db:          db,
		subscribers: map[string]Receiver{},
	}
	return instance, instance, nil
}

func (dag *bboltDAG) Diagnostics() []core.DiagnosticResult {
	result := make([]core.DiagnosticResult, 0)
	result = append(result, headsStatistic{heads: dag.Heads()})
	documentNum := 0
	_ = dag.db.View(func(tx *bbolt.Tx) error {
		if bucket := tx.Bucket([]byte(documentsBucket)); bucket != nil {
			documentNum = bucket.Stats().KeyN
		}
		return nil
	})
	result = append(result, numberOfDocumentsStatistic{numberOfDocuments: documentNum})
	// TODO: https://github.com/nuts-foundation/nuts-node/issues/11
	result = append(result, dataSizeStatistic{sizeInBytes: 0})
	return result
}

func (dag *bboltDAG) Subscribe(documentType string, receiver Receiver) {
	oldSubscriber := dag.subscribers[documentType]
	dag.subscribers[documentType] = func(document Document, payload []byte) error {
		// Chain subscribers in case there's more than 1
		if oldSubscriber != nil {
			if err := oldSubscriber(document, payload); err != nil {
				return err
			}
		}
		return receiver(document, payload)
	}
}

func (dag bboltDAG) ReadPayload(payloadHash hash.SHA256Hash) ([]byte, error) {
	var result []byte
	err := dag.db.View(func(tx *bbolt.Tx) error {
		if payloads := tx.Bucket([]byte(payloadsBucket)); payloads != nil {
			result = payloads.Get(payloadHash.Slice())
		}
		return nil
	})
	return result, err
}

func (dag bboltDAG) WritePayload(payloadHash hash.SHA256Hash, data []byte) error {
	err := dag.db.Update(func(tx *bbolt.Tx) error {
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
		dag.payloadReceived(payloadHash, data)
	}
	return err
}

func (dag bboltDAG) Get(ref hash.SHA256Hash) (Document, error) {
	var result Document
	var err error
	err = dag.db.View(func(tx *bbolt.Tx) error {
		if documents := tx.Bucket([]byte(documentsBucket)); documents != nil {
			result, err = getDocument(ref, documents)
			return err
		}
		return nil
	})
	return result, err
}

func (dag bboltDAG) GetByPayloadHash(payloadHash hash.SHA256Hash) ([]Document, error) {
	result := make([]Document, 0)
	err := dag.db.View(func(tx *bbolt.Tx) error {
		documents := tx.Bucket([]byte(documentsBucket))
		payloadIndex := tx.Bucket([]byte(payloadIndexBucket))
		if documents == nil || payloadIndex == nil {
			return nil
		}
		documentHashes := parseHashList(payloadIndex.Get(payloadHash.Slice()))
		for _, documentHash := range documentHashes {
			document, err := getDocument(documentHash, documents)
			if err != nil {
				return err
			}
			result = append(result, document)
		}
		return nil
	})
	return result, err
}

func (dag bboltDAG) Heads() []hash.SHA256Hash {
	result := make([]hash.SHA256Hash, 0)
	_ = dag.db.View(func(tx *bbolt.Tx) error {
		heads := tx.Bucket([]byte(headsBucket))
		if heads == nil {
			return nil
		}
		cursor := heads.Cursor()
		for ref, _ := cursor.First(); ref != nil; ref, _ = cursor.Next() {
			result = append(result, hash.FromSlice(ref))
		}
		return nil
	})
	return result
}

func (dag bboltDAG) All() ([]Document, error) {
	result := make([]Document, 0)
	err := dag.db.View(func(tx *bbolt.Tx) error {
		if documents := tx.Bucket([]byte(documentsBucket)); documents != nil {
			cursor := documents.Cursor()
			for ref, documentBytes := cursor.First(); documentBytes != nil; ref, documentBytes = cursor.Next() {
				if bytes.Equal(ref, []byte(rootsDocumentKey)) {
					continue
				}
				document, err := ParseDocument(documentBytes)
				if err != nil {
					return fmt.Errorf("unable to parse document %s: %w", ref, err)
				}
				result = append(result, document)
			}
			return nil
		}
		return nil
	})
	return result, err
}

func (dag bboltDAG) IsPresent(ref hash.SHA256Hash) (bool, error) {
	return dag.isPresent(documentsBucket, ref.Slice())
}

func (dag bboltDAG) IsPayloadPresent(payloadHash hash.SHA256Hash) (bool, error) {
	return dag.isPresent(payloadsBucket, payloadHash.Slice())
}

func (dag bboltDAG) MissingDocuments() []hash.SHA256Hash {
	result := make([]hash.SHA256Hash, 0)
	if err := dag.db.View(func(tx *bbolt.Tx) error {
		if bucket := tx.Bucket([]byte(missingDocumentsBucket)); bucket != nil {
			cursor := bucket.Cursor()
			for ref, _ := cursor.First(); ref != nil; ref, _ = cursor.Next() {
				result = append(result, hash.FromSlice(ref))
			}
		}
		return nil
	}); err != nil {
		log.Logger().Errorf("Unable to fetch missing documents: %v", err)
	}
	return result
}

func (dag *bboltDAG) Add(documents ...Document) error {
	for _, document := range documents {
		if document != nil {
			if err := dag.add(document); err != nil {
				return err
			}
		}
	}
	return nil
}

func (dag bboltDAG) Walk(walker Walker, visitor Visitor, startAt hash.SHA256Hash) error {
	return dag.db.View(func(tx *bbolt.Tx) error {
		documents := tx.Bucket([]byte(documentsBucket))
		nexts := tx.Bucket([]byte(nextsBucket))
		if documents == nil || nexts == nil {
			// DAG is empty
			return nil
		}
		return walker.walk(visitor, startAt, func(hash hash.SHA256Hash) (Document, error) {
			return getDocument(hash, documents)
		}, func(hash hash.SHA256Hash) ([]hash.SHA256Hash, error) {
			return parseHashList(nexts.Get(hash.Slice())), nil
		}, documents.Stats().KeyN) // TODO Optimization: should we cache this number of keys?
	})
}

func (dag bboltDAG) Root() (hash hash.SHA256Hash, err error) {
	err = dag.db.View(func(tx *bbolt.Tx) error {
		if documents := tx.Bucket([]byte(documentsBucket)); documents != nil {
			if roots := getRoots(documents); len(roots) >= 1 {
				hash = roots[0]
			}
		}
		return nil
	})
	return
}

func (dag bboltDAG) isPresent(bucketName string, key []byte) (bool, error) {
	var result bool
	var err error
	err = dag.db.View(func(tx *bbolt.Tx) error {
		if payloads := tx.Bucket([]byte(bucketName)); payloads != nil {
			data := payloads.Get(key)
			result = len(data) > 0
		}
		return nil
	})
	return result, err
}

func (dag *bboltDAG) add(document Document) error {
	ref := document.Ref()
	refSlice := ref.Slice()
	return dag.db.Update(func(tx *bbolt.Tx) error {
		documents, nexts, missingDocuments, payloadIndex, _, heads, err := getBuckets(tx)
		if err != nil {
			return err
		}
		if exists(documents, ref) {
			log.Logger().Tracef("Document %s already exists, not adding it again.", ref)
			return nil
		}
		if len(document.Previous()) == 0 {
			if getRoots(documents) != nil {
				return errRootAlreadyExists
			}
			if err := addRoot(documents, ref); err != nil {
				return fmt.Errorf("unable to register root %s: %w", ref, err)
			}
		}
		if err := documents.Put(refSlice, document.Data()); err != nil {
			return err
		}
		// Store forward references ([C -> prev A, B] is stored as [A -> C, B -> C])
		for _, prev := range document.Previous() {
			if err := dag.registerNextRef(nexts, prev, ref); err != nil {
				return fmt.Errorf("unable to store forward reference %s->%s: %w", prev, ref, err)
			}
			if !exists(documents, prev) {
				log.Logger().Debugf("Document %s is referring to missing prev %s, marking it as missing", ref, prev)
				if err = missingDocuments.Put(prev.Slice(), []byte{1}); err != nil {
					return fmt.Errorf("unable to register missing document %s: %w", prev, err)
				}
			}
			if err := heads.Delete(prev.Slice()); err != nil {
				return fmt.Errorf("unable to remove earlier head: %w", err)
			}
		}
		// See if this is a head
		if len(missingDocuments.Get(refSlice)) == 0 {
			// This is not a previously missing document, so it is a head (for now)
			if err := heads.Put(refSlice, []byte{1}); err != nil {
				return fmt.Errorf("unable to mark document as head (ref=%s): %w", ref, err)
			}
		}
		// Store reverse reference from payload hash to document
		newPayloadIndexValue := appendHashList(payloadIndex.Get(document.Payload().Slice()), ref)
		if err = payloadIndex.Put(document.Payload().Slice(), newPayloadIndexValue); err != nil {
			return fmt.Errorf("unable to update payload index for document %s: %w", ref, err)
		}
		// Remove marker if this document was previously missing
		return missingDocuments.Delete(refSlice)
	})
}

func getBuckets(tx *bbolt.Tx) (documents, nexts, missingDocuments, payloadIndex, payloads, heads *bbolt.Bucket, err error) {
	if documents, err = tx.CreateBucketIfNotExists([]byte(documentsBucket)); err != nil {
		return
	}
	if nexts, err = tx.CreateBucketIfNotExists([]byte(nextsBucket)); err != nil {
		return
	}
	if missingDocuments, err = tx.CreateBucketIfNotExists([]byte(missingDocumentsBucket)); err != nil {
		return
	}
	if payloadIndex, err = tx.CreateBucketIfNotExists([]byte(payloadIndexBucket)); err != nil {
		return
	}
	if payloads, err = tx.CreateBucketIfNotExists([]byte(payloadsBucket)); err != nil {
		return
	}
	if heads, err = tx.CreateBucketIfNotExists([]byte(headsBucket)); err != nil {
		return
	}
	return
}

func getRoots(documentsBucket *bbolt.Bucket) []hash.SHA256Hash {
	return parseHashList(documentsBucket.Get([]byte(rootsDocumentKey)))
}

func addRoot(documentsBucket *bbolt.Bucket, ref hash.SHA256Hash) error {
	roots := appendHashList(documentsBucket.Get([]byte(rootsDocumentKey)), ref)
	return documentsBucket.Put([]byte(rootsDocumentKey), roots)
}

// registerNextRef registers a forward reference a.k.a. "next", in contrary to "prev(s)" which is the inverse of the relation.
// It takes the nexts bucket, the prev and the next. Given document A and B where B prevs A, prev = A, next = B.
func (dag *bboltDAG) registerNextRef(nextsBucket *bbolt.Bucket, prev hash.SHA256Hash, next hash.SHA256Hash) error {
	prevSlice := prev.Slice()
	value := nextsBucket.Get(prevSlice)
	if value == nil {
		// No entry yet for this prev
		return nextsBucket.Put(prevSlice, next.Slice())
	}
	// Existing entry for this prev so add this one to it
	return nextsBucket.Put(prevSlice, appendHashList(value, next))
}

func (dag *bboltDAG) payloadReceived(payloadHash hash.SHA256Hash, payload []byte) {
	// TODO: This is a stupid implementation that doesn't retry failed subscribers or publish documents in-order
	// (since documents and payload may arrive out-of-order). Should be changed to something more intelligent.
	err := dag.db.View(func(tx *bbolt.Tx) error {
		documents := tx.Bucket([]byte(documentsBucket))
		payloadsIndex := tx.Bucket([]byte(payloadIndexBucket))
		if documents == nil || payloadsIndex == nil {
			return nil
		}
		for _, documentRef := range parseHashList(payloadsIndex.Get(payloadHash.Slice())) {
			if document, err := getDocument(documentRef, documents); err != nil {
				return err
			} else if receiver := dag.subscribers[document.PayloadType()]; receiver == nil {
				continue
			} else if err := receiver(document, payload); err != nil {
				// TODO: Should this be done in a goroutine to make sure applications don't block network processes?
				log.Logger().Errorf("Document subscriber returned an error (document=%s,type=%s): %v", document.Ref(), document.PayloadType(), err)
			}
		}
		return nil
	})
	if err != nil {
		log.Logger().Errorf("Unable to publish document (payload=%s): %v", payloadHash, err)
	}
}

func getDocument(hash hash.SHA256Hash, documents *bbolt.Bucket) (Document, error) {
	documentBytes := documents.Get(hash.Slice())
	if documentBytes == nil {
		return nil, nil
	}
	document, err := ParseDocument(documentBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse document %s: %w", hash, err)
	}
	return document, nil
}

// exists checks whether the document with the given ref exists.
func exists(documents *bbolt.Bucket, ref hash.SHA256Hash) bool {
	return documents.Get(ref.Slice()) != nil
}

// parseHashList splits a list of concatenated hashes into separate hashes.
func parseHashList(input []byte) []hash.SHA256Hash {
	if len(input) == 0 {
		return nil
	}
	num := (len(input) - (len(input) % hash.SHA256HashSize)) / hash.SHA256HashSize
	result := make([]hash.SHA256Hash, num)
	for i := 0; i < num; i++ {
		result[i] = hash.FromSlice(input[i*hash.SHA256HashSize : i*hash.SHA256HashSize+hash.SHA256HashSize])
	}
	return result
}

func appendHashList(list []byte, h hash.SHA256Hash) []byte {
	newList := make([]byte, 0, len(list)+hash.SHA256HashSize)
	newList = append(newList, list...)
	newList = append(newList, h.Slice()...)
	return newList
}
