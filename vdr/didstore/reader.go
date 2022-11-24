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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
)

func readDocument(tx stoabs.ReadTx, documentHash hash.SHA256Hash) (did.Document, error) {
	var document did.Document
	documentReader := tx.GetShelfReader(documentShelf)
	documentBytes, err := documentReader.Get(stoabs.NewHashKey(documentHash))
	if err != nil {
		return document, fmt.Errorf("readDocument: database error on document read: %w", err)
	}
	if len(documentBytes) == 0 {
		return document, types.ErrNotFound
	}
	if err := json.Unmarshal(documentBytes, &document); err != nil {
		return document, fmt.Errorf("readDocument: unmarshal error on document: %w", err)
	}

	return document, nil
}

func readMetadata(tx stoabs.ReadTx, ref []byte) (documentMetadata, error) {
	var metadata documentMetadata
	metadataReader := tx.GetShelfReader(metadataShelf)
	metadataBytes, err := metadataReader.Get(stoabs.BytesKey(ref))
	if err != nil {
		return metadata, fmt.Errorf("readMetadata: database error on documentMetadata read: %w", err)
	}
	if len(metadataBytes) == 0 {
		return metadata, errors.New("readMetadata: documentMetadata not found")
	}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return metadata, fmt.Errorf("readMetadata: unmarshal error on documentMetadata: %w", err)
	}

	return metadata, nil
}

func readDocumentForEvent(tx stoabs.ReadTx, e event) (*did.Document, *documentMetadata, error) {
	currentDocument := did.Document{}
	currentMetadata := documentMetadata{}

	// newly created event hold document and documentMetadata
	if e.document != nil {
		return e.document, e.metadata, nil
	}

	documentReader := tx.GetShelfReader(documentShelf)
	metadataReader := tx.GetShelfReader(metadataShelf)
	docBytes, err := documentReader.Get(stoabs.HashKey(e.DocRef))
	if err != nil {
		return nil, nil, fmt.Errorf("readDocumentForEvent: database error on document read: %w", err)
	}
	if len(docBytes) == 0 {
		return nil, nil, types.ErrNotFound
	}
	err = json.Unmarshal(docBytes, &currentDocument)
	if err != nil {
		return nil, nil, fmt.Errorf("readDocumentForEvent: unmarshal error on document: %w", err)
	}

	metadataBytes, err := metadataReader.Get(stoabs.BytesKey(e.MetaRef))
	if err != nil {
		return nil, nil, fmt.Errorf("readDocumentForEvent: database error on documentMetadata read: %w", err)
	}
	err = json.Unmarshal(metadataBytes, &currentMetadata)
	if err != nil {
		return nil, nil, fmt.Errorf("readDocumentForEvent: unmarshal error on documentMetadata: %w", err)
	}
	return &currentDocument, &currentMetadata, nil
}

func readEventList(tx stoabs.ReadTx, id did.DID) (eventList, error) {
	el := eventList{}
	eventReader := tx.GetShelfReader(eventShelf)
	eventListBytes, err := eventReader.Get(stoabs.BytesKey(id.String()))
	if err != nil {
		return el, fmt.Errorf("readEventList: database error on events read: %w", err)
	}
	if len(eventListBytes) == 0 {
		return el, nil
	}

	err = json.Unmarshal(eventListBytes, &el)
	if err != nil {
		return el, fmt.Errorf("readEventList: unmarshall on eventList: %w", err)
	}
	return el, nil
}

func isDuplicate(tx stoabs.ReadTx, transaction Transaction) bool {
	txReader := tx.GetShelfReader(transactionIndexShelf)
	bytes, err := txReader.Get(stoabs.HashKey(transaction.Ref))
	if err == nil && len(bytes) > 0 {
		return true
	}
	return false
}
