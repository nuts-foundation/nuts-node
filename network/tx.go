package network

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"time"
)

// NewTXTemplate creates a new TransactionTemplate with the given required properties.
func NewTXTemplate(payloadType string, payload []byte, key crypto.Key) TransactionTemplate {
	return TransactionTemplate{
		payloadType: payloadType,
		payload:     payload,
		key:         key,
	}
}

// TransactionTemplate is used to build a spec for new transactions.
type TransactionTemplate struct {
	key             crypto.Key
	payload         []byte
	payloadType     string
	attachKey       bool
	timestamp       time.Time
	additionalPrevs []hash.SHA256Hash
	participants    dag.PAL
}

// WithAttachKey specifies that the signing key must be attached to the transaction, because it wasn't published before.
func (t TransactionTemplate) WithAttachKey() TransactionTemplate {
	t.attachKey = true
	return t
}

// WithTimestamp specifies a custom signing time for the transaction. Otherwise, time.Now() is used.
func (t TransactionTemplate) WithTimestamp(timestamp time.Time) TransactionTemplate {
	t.timestamp = timestamp
	return t
}

// WithAdditionalPrevs specifies additional `prev` hashes, which are added to the set of prevs of the new transaction (current HEADs of the DAG).
// This is used to update entities that are mutable. By referring to the previous transaction of an entity, conflicts through parallel updates can be detected.
func (t TransactionTemplate) WithAdditionalPrevs(additionalPrevs []hash.SHA256Hash) TransactionTemplate {
	t.additionalPrevs = additionalPrevs
	return t
}

// WithPrivate specifies that the transaction is private, and should only be readable by the given Participants.
func (t TransactionTemplate) WithPrivate(participants []did.DID) TransactionTemplate {
	t.participants = participants
	return t
}

// PayloadType returns the set payload type.
func (t TransactionTemplate) PayloadType() string {
	return t.payloadType
}

// AttachKey returns the set attachKey value.
func (t TransactionTemplate) AttachKey() bool {
	return t.attachKey
}

// Key returns the set key value.
func (t TransactionTemplate) Key() crypto.Key {
	return t.key
}
