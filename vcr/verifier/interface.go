package verifier

import (
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"io"
	"time"
)

// Verifier defines the interface for verifying verifiable credentials.
type Verifier interface {
	// Verify checks credential on full correctness. It checks:
	// validity of the signature
	// if it has been revoked
	// if the issuer is registered as trusted
	Verify(credential vc.VerifiableCredential, allowUntrusted bool, checkSignature bool, validAt *time.Time) error
	// Validate checks the verifiable credential technical correctness
	Validate(credentialToVerify vc.VerifiableCredential, at *time.Time) error
	// IsRevoked checks if the credential is revoked
	IsRevoked(credentialID ssi.URI) (bool, error)
	// RegisterRevocation stores the revocation in the store
	// before storing the revocation gets validated
	RegisterRevocation(revocation credential.Revocation) error
}

// ErrNotFound is returned when a credential or revocation can not be found based on its ID.
var ErrNotFound = errors.New("not found")

// Store defines the interface for a store for a verifier.
// The store is filled with public information such as revoked credentials,
// as well as local defined trust relations between issuer and credential type.
type Store interface {
	// GetRevocation find the revocation by the credential ID
	// Returns an ErrNotFound when the revocation is not in the store
	GetRevocation(id ssi.URI) (*credential.Revocation, error)
	// StoreRevocation writes a revocation to storage.
	StoreRevocation(r credential.Revocation) error
	// Closer closes and frees the underlying resources the store uses.
	io.Closer
}
