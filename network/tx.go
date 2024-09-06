/*
 * Copyright (C) 2021 Nuts community
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

package network

import (
	"crypto"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
)

// TransactionTemplate creates a new Template with the given required properties.
func TransactionTemplate(payloadType string, payload []byte, kid string) Template {
	return Template{
		Type:    payloadType,
		Payload: payload,
		KID:     kid,
	}
}

// Template is used to build a spec for new transactions.
type Template struct {
	KID             string
	Payload         []byte
	PublicKey       crypto.PublicKey
	Type            string
	Timestamp       time.Time
	AdditionalPrevs []hash.SHA256Hash
	Participants    dag.PAL
}

// WithAttachKey specifies that the signing key must be attached to the transaction, because it wasn't published before.
func (t Template) WithAttachKey(key crypto.PublicKey) Template {
	t.PublicKey = key
	return t
}

// WithTimestamp specifies a custom signing time for the transaction. Otherwise, time.Now() is used.
func (t Template) WithTimestamp(timestamp time.Time) Template {
	t.Timestamp = timestamp
	return t
}

// WithAdditionalPrevs specifies additional `prev` hashes, which are added to the set of prevs of the new transaction (current HEADs of the DAG).
// This is used to update entities that are mutable. By referring to the previous transaction of an entity, conflicts through parallel updates can be detected.
func (t Template) WithAdditionalPrevs(additionalPrevs []hash.SHA256Hash) Template {
	t.AdditionalPrevs = additionalPrevs
	return t
}

// WithPrivate specifies that the transaction is private, and should only be readable by the given Participants.
func (t Template) WithPrivate(participants []did.DID) Template {
	t.Participants = participants
	return t
}
