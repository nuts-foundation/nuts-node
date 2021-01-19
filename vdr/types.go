package vdr

import (
	"errors"
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-network/pkg/model"
)

var ErrUpdateOnOutdatedData = errors.New("could not update outdated document")
// ErrInvalidDID The DID supplied to the DID resolution function does not conform to valid syntax.0
var ErrInvalidDID = errors.New("invalid did syntax")
// ErrNotFound The DID resolver was unable to find the DID document resulting from this resolution request.
var ErrNotFound = errors.New("unable to find the did document")
// ErrDeactivated The DID supplied to the DID resolution function has been deactivated.
var ErrDeactivated = errors.New("the document has been deactivated")

// DocReader is the interface that groups all the DID Document read methods
// Get returns the DID document using on the given DID or ErrNotFound if not found.
// If something goes wrong an error is returned.
type DocReader interface {
	Get(DID did.DID) (*did.Document, *DocumentMetadata, error)
}

// DocWriter is the interface that groups al the DID Document write methods
type DocWriter interface {
	// Create creates a new DID document and returns it. If something goes wrong an error is returned.
	Create() (*did.Document, error)

	// Update replaces the DID document identified by DID with the nextVersion
	// To prevent updating state data a hash of the current version should be provided.
	// If the given hash does not represents the current version, a ErrUpdateOnOutdatedData is returned
	// If the DID Document is not found or not local a ErrNotFound is returned
	// If the DID Document is not active a ErrDeactivated is returned
	Update(DID did.DID, hash []byte, nextVersion did.Document) (*did.Document, error)
}

// Store is the interface that groups all operations on DID documents.
type Store interface {
	DocReader
	DocWriter
}

// DocumentMetadata holds the metadata of a DID document
type DocumentMetadata struct {
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated,omitempty"`
	// Version contains the semantic version of the DID document.
	Version int `json:"version"`
	// OriginJWSHash contains the hash of the JWS envelope of the first version of the DID document.
	OriginJWSHash model.Hash `json:"originJwsHash"`
	// Hash of DID document bytes. Is equal to payloadHash in network layer.
	Hash string `json:"hash"`
	// Tags of the DID document.
	Tags []string `json:"tags,omitempty"`
}
