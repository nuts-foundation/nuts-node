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
 */

package didstore

import (
	"encoding/binary"
	"encoding/json"
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
		return fmt.Errorf("writeEventList: database error: %w", err)
	}
	return nil
}

func writeDocument(tx stoabs.WriteTx, didDocument did.Document, transaction Transaction) error {
	var (
		documentWriter stoabs.Writer
		documentBytes  []byte
	)
	// transaction
	transactionWriter := tx.GetShelfWriter(transactionIndexShelf)
	err := transactionWriter.Put(stoabs.HashKey(transaction.Ref), []byte{0})
	if err != nil {
		return fmt.Errorf("writeDocument: database error on txRef write: %w", err)
	}

	// document
	documentWriter = tx.GetShelfWriter(documentShelf)
	documentBytes, err = json.Marshal(didDocument)
	if err != nil {
		return fmt.Errorf("writeDocument: marshalling DID Document: %w", err)
	}
	err = documentWriter.Put(stoabs.HashKey(transaction.PayloadHash), documentBytes)
	if err != nil {
		return fmt.Errorf("writeDocument: database error on document write: %w", err)
	}
	return nil
}

func writeLatest(tx stoabs.WriteTx, id did.DID, metadata documentMetadata) error {
	// store latest
	latestWriter := tx.GetShelfWriter(latestShelf)

	// store updated eventList (return new list?)
	mdID := fmt.Sprintf("%s%d", id.String(), metadata.Version)
	err := latestWriter.Put(stoabs.BytesKey(id.String()), []byte(mdID))
	if err != nil {
		return fmt.Errorf("writeDocument: database error on latest write: %w", err)
	}
	return nil
}

func applyFrom(tx stoabs.WriteTx, base *event, applyList []event) error {
	var document *did.Document
	var metadata *documentMetadata
	var err error

	// for updating conflicted stats
	var conflicted bool
	var conflictedCount uint32
	statsWriter := tx.GetShelfWriter(statsShelf)
	conflictedWriter := tx.GetShelfWriter(conflictedShelf)
	cBytes, err := statsWriter.Get(stoabs.BytesKey(conflictedCountKey))
	if err != nil {
		return fmt.Errorf("applyFrom: database error on conflictedCount read: %w", err)
	}
	if len(cBytes) > 0 {
		conflictedCount = binary.BigEndian.Uint32(cBytes)
	}

	if base != nil {
		// get DID Document and documentMetadata for base
		d, err := readDocument(tx, base.DocRef)
		if err != nil {
			return err
		}
		document = &d
		m, err := readMetadata(tx, []byte(base.MetaRef))
		if err != nil {
			return err
		}
		metadata = &m
		b, err := conflictedWriter.Get(stoabs.BytesKey(document.ID.String()))
		if err != nil {
			return fmt.Errorf("applyFrom: database error on conflicted read: %w", err)
		}
		if len(b) > 0 {
			// it was already conflicted
			conflicted = true
		}
	}

	for _, nextEvent := range applyList {
		document, metadata, err = applyEvent(tx, document, metadata, nextEvent)
		if err != nil {
			return err
		}
	}

	if metadata.isConflicted() {
		if !conflicted {
			conflictedCount++
		}
		err = conflictedWriter.Put(stoabs.BytesKey(document.ID.String()), []byte{0})
	} else {
		if conflicted {
			conflictedCount--
		}
		err = conflictedWriter.Delete(stoabs.BytesKey(document.ID.String()))
	}
	if err != nil {
		return fmt.Errorf("applyFrom: database error on conflicted write: %w", err)
	}
	cBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(cBytes, conflictedCount)
	err = statsWriter.Put(stoabs.BytesKey(conflictedCountKey), cBytes)
	if err != nil {
		return fmt.Errorf("applyFrom: database error on conflictedCount write: %w", err)
	}

	// new document
	if metadata.Version == 0 {
		if err = incrementDocumentCount(tx); err != nil {
			return err
		}
	}

	return writeLatest(tx, document.ID, *metadata)
}

func incrementDocumentCount(tx stoabs.WriteTx) error {
	docCount := uint32(0)
	statsWriter := tx.GetShelfWriter(statsShelf)
	cBytes, err := statsWriter.Get(stoabs.BytesKey(documentCountKey))
	if err != nil {
		return fmt.Errorf("incrementDocumentCount: database error on read: %w", err)
	}
	if len(cBytes) > 0 {
		docCount = binary.BigEndian.Uint32(cBytes)
	}

	cBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(cBytes, docCount+1)
	err = statsWriter.Put(stoabs.BytesKey(documentCountKey), cBytes)
	if err != nil {
		return fmt.Errorf("incrementDocumentCount: database error on write: %w", err)
	}
	return nil
}

func applyEvent(tx stoabs.WriteTx, latestDocument *did.Document, latestMetadata *documentMetadata, nextEvent event) (*did.Document, *documentMetadata, error) {
	nextDocument, err := readDocument(tx, nextEvent.DocRef)
	if err != nil {
		return nil, nil, err
	}
	nextMetadata := documentMetadata{
		Created:             nextEvent.Created,
		Updated:             nextEvent.Created,
		Hash:                nextEvent.DocRef,
		PreviousTransaction: nextEvent.TXPrev,
		SourceTransactions:  []hash.SHA256Hash{nextEvent.TXRef},
		Deactivated:         isDeactivated(nextDocument),
	}
	if latestMetadata != nil {
		nextMetadata.Version = latestMetadata.Version + 1
		nextMetadata.Created = latestMetadata.Created
		nextMetadata.PreviousHash = &latestMetadata.Hash
	}

	nextDocument, nextMetadata = applyDocument(latestDocument, latestMetadata, nextDocument, nextMetadata)
	metadataBytes, _ := json.Marshal(nextMetadata)
	metadataWriter := tx.GetShelfWriter(metadataShelf)
	if err = metadataWriter.Put(stoabs.BytesKey(fmt.Sprintf("%s%d", nextDocument.ID.String(), nextMetadata.Version)), metadataBytes); err != nil {
		return &nextDocument, &nextMetadata, fmt.Errorf("applyEvent: database error on documentMetadata write: %w", err)
	}

	// if conflicted write nextDocument
	if nextMetadata.isConflicted() {
		docBytes, _ := json.Marshal(nextDocument)
		documentWriter := tx.GetShelfWriter(documentShelf)
		if err = documentWriter.Put(stoabs.HashKey(nextMetadata.Hash), docBytes); err != nil {
			return &nextDocument, &nextMetadata, fmt.Errorf("applyEvent: database error on document write: %w", err)
		}
	}

	return &nextDocument, &nextMetadata, nil
}

func applyDocument(currentDoc *did.Document, currentMeta *documentMetadata, newDoc did.Document, newMeta documentMetadata) (did.Document, documentMetadata) {
	if currentDoc == nil {
		return newDoc, newMeta
	}

	// these can already be updated
	newMeta.Version = currentMeta.Version + 1
	newMeta.Created = currentMeta.Created
	newMeta.Deactivated = isDeactivated(newDoc)
	newMeta.PreviousHash = &currentMeta.Hash

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
		return newDoc, newMeta
	}

	for k := range unconsumed {
		st, _ := hash.ParseHex(k)
		newMeta.SourceTransactions = append(newMeta.SourceTransactions, st)
	}
	newDoc = mergeDocuments(*currentDoc, newDoc)
	newDocBytes, _ := json.Marshal(newDoc)

	newMeta.Hash = hash.SHA256Sum(newDocBytes)
	newMeta.Deactivated = isDeactivated(newDoc)

	return newDoc, newMeta
}

func isDeactivated(document did.Document) bool {
	return len(document.Controller) == 0 && len(document.CapabilityInvocation) == 0
}
