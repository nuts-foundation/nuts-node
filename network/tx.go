package network

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"time"
)

// TransactionTemplate creates a new Template with the given required properties.
func TransactionTemplate(payloadType string, payload []byte, key crypto.Key) Template {
	return Template{
		Type:    payloadType,
		Payload: payload,
		Key:     key,
	}
}

// Template is used to build a spec for new transactions.
type Template struct {
	Key             crypto.Key
	Payload         []byte
	Type            string
	AttachKey       bool
	Timestamp       time.Time
	AdditionalPrevs []hash.SHA256Hash
	Participants    dag.PAL
}

// WithAttachKey specifies that the signing key must be attached to the transaction, because it wasn't published before.
func (t Template) WithAttachKey() Template {
	t.AttachKey = true
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
