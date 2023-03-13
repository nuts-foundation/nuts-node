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
	if err != nil && !errors.Is(err, stoabs.ErrKeyNotFound) {
		return document, err
	}
	if len(documentBytes) == 0 {
		return document, types.ErrNotFound
	}
	if err := json.Unmarshal(documentBytes, &document); err != nil {
		return document, fmt.Errorf("unmarshal error on document: %w", err)
	}

	return document, nil
}

func readDocumentFromEvent(tx stoabs.ReadTx, e event) (did.Document, error) {
	if e.document != nil {
		return *e.document, nil
	}
	return readDocument(tx, e.PayloadHash)
}

func readMetadata(tx stoabs.ReadTx, ref []byte) (documentMetadata, error) {
	var metadata documentMetadata
	metadataReader := tx.GetShelfReader(metadataShelf)
	metadataBytes, err := metadataReader.Get(stoabs.BytesKey(ref))
	if err != nil && !errors.Is(err, stoabs.ErrKeyNotFound) {
		return metadata, err
	}
	if len(metadataBytes) == 0 {
		return metadata, errors.New("documentMetadata not found")
	}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return metadata, fmt.Errorf("unmarshal error on documentMetadata: %w", err)
	}

	return metadata, nil
}

func readEventList(tx stoabs.ReadTx, id did.DID) (eventList, error) {
	el := eventList{}
	eventReader := tx.GetShelfReader(eventShelf)
	eventListBytes, err := eventReader.Get(stoabs.BytesKey(id.String()))
	if err != nil && !errors.Is(err, stoabs.ErrKeyNotFound) {
		return el, err
	}
	if len(eventListBytes) == 0 {
		// New DID Document to be created, no existing events to be found.
		return el, nil
	}

	err = json.Unmarshal(eventListBytes, &el)
	if err != nil {
		return el, fmt.Errorf("unmarshal error on eventList: %w", err)
	}
	return el, nil
}

func transactionExists(tx stoabs.ReadTx, ref hash.SHA256Hash) (bool, error) {
	txReader := tx.GetShelfReader(transactionIndexShelf)
	bytes, err := txReader.Get(stoabs.HashKey(ref))
	if err != nil && !errors.Is(err, stoabs.ErrKeyNotFound) {
		return false, err
	}
	return len(bytes) > 0, nil
}
