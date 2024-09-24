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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

func writeEventList(tx stoabs.WriteTx, newEventList eventList, id did.DID) error {
	// update MetaRefs
	for i := range newEventList.Events {
		newEventList.Events[i].MetaRef = fmt.Sprintf("%s%d", id.String(), i)
	}

	nelBytes, _ := json.Marshal(newEventList)
	eventShelf := tx.GetShelfWriter(eventShelf)
	err := eventShelf.Put(stoabs.BytesKey(id.String()), nelBytes)
	if err != nil {
		return err
	}
	return nil
}

func writeDocument(tx stoabs.WriteTx, didDocument did.Document, transaction Transaction) error {
	// transaction
	transactionWriter := tx.GetShelfWriter(transactionIndexShelf)
	err := transactionWriter.Put(stoabs.HashKey(transaction.Ref), transaction.PayloadHash.Slice())
	if err != nil {
		return err
	}

	// document
	documentWriter := tx.GetShelfWriter(documentShelf)
	documentBytes, err := json.Marshal(didDocument)
	if err != nil {
		return fmt.Errorf("marshalling DID Document: %w", err)
	}
	err = documentWriter.Put(stoabs.HashKey(transaction.PayloadHash), documentBytes)
	if err != nil {
		return err
	}
	return nil
}

func writeLatest(tx stoabs.WriteTx, id did.DID, metadata documentMetadata) error {
	// store latest
	latestWriter := tx.GetShelfWriter(latestShelf)

	// store updated eventList (return new list?)
	mdID := fmt.Sprintf("%s%d", id, metadata.Version)
	err := latestWriter.Put(stoabs.BytesKey(id.String()), []byte(mdID))
	if err != nil {
		return err
	}
	return nil
}

// applyFrom takes a base Event as a reference point and applies all events from applyList.
// The reference point is the latest DID Document and metadata that were updated before the new event that has been received.
// Because all other updates may depend on the newly received event, all have to be re-added as if just received.
// This is needed because the newly received event might resolve a conflict (or causes one) which will probably
// propagate to the latest state.
// The conflicted count and total number of documents statistic is updated here as well.
// These need to be updated here since all reading of current stats have to happen before any writing is done.
// This ensures the same behaviour between bbolt and redis.
func (tl *store) applyFrom(tx stoabs.WriteTx, base *event, applyList []event) error {
	var document *did.Document
	var metadata *documentMetadata
	var err error

	// for updating conflicted stats
	var conflicted bool
	var conflictedCount uint32
	statsWriter := tx.GetShelfWriter(statsShelf)
	conflictedWriter := tx.GetShelfWriter(conflictedShelf)
	cBytes, err := statsWriter.Get(stoabs.BytesKey(conflictedCountKey))
	if err != nil && !errors.Is(err, stoabs.ErrKeyNotFound) {
		return err
	}
	if len(cBytes) > 0 {
		conflictedCount = binary.BigEndian.Uint32(cBytes)
	}

	if base != nil {
		// get DID Document and documentMetadata for base
		d, err := readDocument(tx, base.PayloadHash)
		if err != nil {
			return fmt.Errorf("read document failed: %w", err)
		}
		document = &d
		// get documentMetadata for base
		m, err := readMetadata(tx, []byte(base.MetaRef))
		if err != nil {
			return fmt.Errorf("read metadata failed: %w", err)
		}
		metadata = &m
		b, err := conflictedWriter.Get(stoabs.BytesKey(document.ID.String()))
		if err != nil && !errors.Is(err, stoabs.ErrKeyNotFound) {
			return err
		}
		if len(b) > 0 {
			// it was already conflicted
			conflicted = true
		}
	}

	for _, nextEvent := range applyList {
		document, metadata, err = applyEvent(tx, metadata, nextEvent)
		if err != nil {
			return fmt.Errorf("applying event failed: %w", err)
		}
	}

	if metadata.isConflicted() {
		if !conflicted {
			conflictedCount++
		}
		tl.addCachedConflict(*document, *metadata)
		err = conflictedWriter.Put(stoabs.BytesKey(document.ID.String()), []byte{0})
	} else {
		if conflicted {
			conflictedCount--
		}
		tl.removeCachedConflict(*document)
		err = conflictedWriter.Delete(stoabs.BytesKey(document.ID.String()))
	}
	if err != nil {
		return err
	}
	cBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(cBytes, conflictedCount)
	err = statsWriter.Put(stoabs.BytesKey(conflictedCountKey), cBytes)
	if err != nil {
		return err
	}

	// new document
	if metadata.Version == 0 {
		if err = incrementDocumentCount(tx); err != nil {
			return fmt.Errorf("increment document count failed: %w", err)
		}
	}

	return writeLatest(tx, document.ID, *metadata)
}

func incrementDocumentCount(tx stoabs.WriteTx) error {
	docCount := uint32(0)
	statsWriter := tx.GetShelfWriter(statsShelf)
	cBytes, err := statsWriter.Get(stoabs.BytesKey(documentCountKey))
	if err != nil && !errors.Is(err, stoabs.ErrKeyNotFound) {
		return err
	}
	if len(cBytes) > 0 {
		docCount = binary.BigEndian.Uint32(cBytes)
	}

	cBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(cBytes, docCount+1)
	err = statsWriter.Put(stoabs.BytesKey(documentCountKey), cBytes)
	if err != nil {
		return err
	}
	return nil
}

func applyEvent(tx stoabs.WriteTx, latestMetadata *documentMetadata, nextEvent event) (*did.Document, *documentMetadata, error) {
	nextDocument, err := readDocumentFromEvent(tx, nextEvent)
	if err != nil {
		return nil, nil, fmt.Errorf("read document failed: %w", err)
	}
	// create nextMetadata based on this event and some defaults.
	// For the initial DID document this does not change. (latestMetadata = nil)
	// For DID updates, applyDocument will make changes.
	nextMetadata := documentMetadata{
		Created:             nextEvent.SigningTime,
		Updated:             nextEvent.SigningTime,
		Hash:                nextEvent.PayloadHash,
		PreviousTransaction: nextEvent.Previous,
		SourceTransactions:  []hash.SHA256Hash{nextEvent.Ref},
		Deactivated:         isDeactivated(nextDocument),
	}

	nextDocument, nextMetadata, err = applyDocument(tx, latestMetadata, nextDocument, nextMetadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to apply next document: %w", err)
	}
	metadataBytes, _ := json.Marshal(nextMetadata)
	metadataWriter := tx.GetShelfWriter(metadataShelf)
	if err = metadataWriter.Put(stoabs.BytesKey(fmt.Sprintf("%s%d", nextDocument.ID.String(), nextMetadata.Version)), metadataBytes); err != nil {
		return nil, nil, err
	}

	// if conflicted write nextDocument
	if nextMetadata.isConflicted() {
		docBytes, _ := json.Marshal(nextDocument)
		documentWriter := tx.GetShelfWriter(documentShelf)
		if err = documentWriter.Put(stoabs.HashKey(nextMetadata.Hash), docBytes); err != nil {
			return nil, nil, err
		}
	}

	return &nextDocument, &nextMetadata, nil
}

func applyDocument(tx stoabs.ReadTx, currentMeta *documentMetadata, newDoc did.Document, newMeta documentMetadata) (did.Document, documentMetadata, error) {
	if currentMeta == nil {
		return newDoc, newMeta, nil
	}

	// these can already be updated
	newMeta.Version = currentMeta.Version + 1
	newMeta.Created = currentMeta.Created
	newMeta.PreviousHash = &currentMeta.Hash
	newMeta.Deactivated = newMeta.Deactivated || currentMeta.Deactivated // once deactivated is always deactivated

	unconsumed := map[string]struct{}{}
outer:
	for _, st := range currentMeta.SourceTransactions {
		for _, ref := range newMeta.PreviousTransaction {
			if st.Equals(ref) {
				continue outer
			}
		}
		unconsumed[st.String()] = struct{}{}
	}
	// if new document consumes all the old TXs, just return the new one
	if len(unconsumed) == 0 {
		return newDoc, newMeta, nil
	}

	txRefReader := tx.GetShelfReader(transactionIndexShelf)
	for k := range unconsumed {
		st, _ := hash.ParseHex(k)
		newMeta.SourceTransactions = append(newMeta.SourceTransactions, st)
		// get old doc by txRef ...
		payloadHashBytes, err := txRefReader.Get(stoabs.HashKey(st))
		if err != nil && !errors.Is(err, stoabs.ErrKeyNotFound) {
			return did.Document{}, documentMetadata{}, fmt.Errorf("error on reading transactionIndexShelf: %w", err)
		}
		if len(payloadHashBytes) == 0 {
			return did.Document{}, documentMetadata{}, fmt.Errorf("transaction reference %s not found on transactionIndexShelf: %w", k, err)
		}
		oldDoc, err := readDocument(tx, hash.FromSlice(payloadHashBytes))
		if err != nil {
			return did.Document{}, documentMetadata{}, fmt.Errorf("read document failed: %w", err)
		}
		newDoc = mergeDocuments(oldDoc, newDoc)
	}
	newDocBytes, _ := json.Marshal(newDoc)

	newMeta.Hash = hash.SHA256Sum(newDocBytes)

	return newDoc, newMeta, nil
}

func isDeactivated(document did.Document) bool {
	return len(document.Controller) == 0 && len(document.CapabilityInvocation) == 0
}
