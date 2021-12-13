package network

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"time"
)

// NewTransaction creates a new TransactionBuilder with the given required properties.
func NewTransaction(payloadType string, payload []byte, key crypto.Key) TransactionBuilder {
	return TransactionBuilder{
		PayloadType: payloadType,
		Payload:     payload,
		Key:         key,
	}
}

// TransactionBuilder is used to build a spec for new transactions.
type TransactionBuilder struct {
	Key             crypto.Key
	Payload         []byte
	PayloadType     string
	AttachKey       bool
	Timestamp       time.Time
	AdditionalPrevs []hash.SHA256Hash
	Participants    []did.DID
}

// WithAttachKey specifies that the signing key must be attached to the transaction, because it wasn't published before.
func (t TransactionBuilder) WithAttachKey() TransactionBuilder {
	t.AttachKey = true
	return t
}

// WithTimestamp specifies a custom signing time for the transaction. Otherwise, time.Now() is used.
func (t TransactionBuilder) WithTimestamp(timestamp time.Time) TransactionBuilder {
	t.Timestamp = timestamp
	return t
}

// WithAdditionalPrevs specifies additional `prev` hashes, which are added to the set of prevs of the new transaction (current HEADs of the DAG).
// This is used to update entities that are mutable. By referring to the previous transaction of an entity, conflicts through parallel updates can be detected.
func (t TransactionBuilder) WithAdditionalPrevs(additionalPrevs []hash.SHA256Hash) TransactionBuilder {
	t.AdditionalPrevs = additionalPrevs
	return t
}

// WithPrivate specifies that the transaction is private, and should only be readable by the given Participants.
func (t TransactionBuilder) WithPrivate(participants []did.DID) TransactionBuilder {
	t.Participants = participants
	return t
}
