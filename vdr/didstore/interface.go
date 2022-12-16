package didstore

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"time"
)

// Store is the interface that groups all low level VDR DID storage operations.
type Store interface {
	// Add a DID Document to the store. The store will place it on the timeline and reprocess other versions if needed
	Add(didDocument did.Document, transaction Transaction) error
	// Conflicted iterates over all conflicted documents
	Conflicted(fn vdr.DocIterator) error
	// ConflictedCount returns the number of conflicted DID Documents
	ConflictedCount() (uint, error)
	// DocumentCount returns the number of DID Documents
	DocumentCount() (uint, error)
	// Iterate loops over all the latest versions of the stored DID Documents and applies fn.
	// Calling any of the Store's functions from the given fn might cause a deadlock.
	Iterate(fn vdr.DocIterator) error
	// Resolve returns the DID Document for the provided DID.
	// If metadata is not provided the latest version is returned.
	// If metadata is provided then the result is filtered or scoped on that metadata.
	// It returns vdr.ErrNotFound if there are no corresponding DID documents or when the DID Documents are disjoint with the provided ResolveMetadata.
	// It returns vdr.ErrDeactivated if no metadata is given and the latest version of the DID Document is deactivated.
	Resolve(id did.DID, metadata *vdr.ResolveMetadata) (*did.Document, *vdr.DocumentMetadata, error)
}

type Transaction struct {
	Clock       uint32
	PayloadHash hash.SHA256Hash
	Previous    []hash.SHA256Hash
	Ref         hash.SHA256Hash
	SigningTime time.Time
}

func (t Transaction) toEvent() event {
	return event{
		Created: t.SigningTime,
		Clock:   t.Clock,
		TXRef:   t.Ref,
		DocRef:  t.PayloadHash,
	}
}
