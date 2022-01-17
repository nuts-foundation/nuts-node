package issuer

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"time"
)

// IssuedCredentialsStore allows an Issuer to store and retrieve issued credentials.
// This is useful for when the issuer wants to revoke a credential.
type IssuedCredentialsStore interface {
	Store(verifiableCredential vc.VerifiableCredential) error
	Search(credentialType string, credentialSubject string, issuer did.DID, subject ssi.URI) ([]vc.VerifiableCredential, error)
}

// Publisher publishes new credentials and revocations to a channel. Used by a credential issuer.
type Publisher interface {
	PublishCredential(verifiableCredential vc.VerifiableCredential, public bool) error
	PublishRevocation(revocation credential.Revocation) error
}

type keyResolver interface {
	ResolveAssertionKey(issuerDID did.DID) (crypto.Key, error)
}

// Store defines the interface for a issuer store. An implementation stores all the issued credentials and the revocations.
type Store interface {
	// StoreCredential writes a VC to storage. Before writing, it calls Verify!
	// It can handle duplicates.
	StoreCredential(vc vc.VerifiableCredential, validAt *time.Time) error
	// StoreRevocation writes a revocation to storage.
	StoreRevocation(r credential.Revocation) error
}
