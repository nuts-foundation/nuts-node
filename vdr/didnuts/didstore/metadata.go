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
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// documentMetadata is like VDR documentMetadata but usable for storage
type documentMetadata struct {
	Version int       `json:"version"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
	// Hash of DID document bytes. Is equal to payloadHash in network layer.
	Hash hash.SHA256Hash `json:"hash"`
	// PreviousHash of the previous version of this DID document
	PreviousHash *hash.SHA256Hash `json:"previoushash,omitempty"`
	// PreviousTransaction contains the prevs header. Used for conflict detection
	PreviousTransaction []hash.SHA256Hash `json:"txprevs"`
	// SourceTransactions points to the transaction(s) that created the current version of this DID Document.
	// If multiple transactions are listed, the DID Document is conflicted
	SourceTransactions []hash.SHA256Hash `json:"txs"`
	// Deactivated indicates if the document is deactivated
	Deactivated bool `json:"deactivated"`
}

func (md documentMetadata) asVDRMetadata() resolver.DocumentMetadata {
	result := resolver.DocumentMetadata{
		Created:            md.Created,
		Hash:               md.Hash,
		PreviousHash:       md.PreviousHash,
		SourceTransactions: md.SourceTransactions,
		Deactivated:        md.Deactivated,
	}
	if !md.Created.Equal(md.Updated) {
		result.Updated = &md.Updated
	}

	return result
}

func (md documentMetadata) isConflicted() bool {
	return len(md.SourceTransactions) > 1
}
