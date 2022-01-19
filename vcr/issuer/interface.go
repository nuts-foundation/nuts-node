package issuer

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"time"
)

// Publisher publishes new credentials and revocations to a channel. Used by a credential issuer.
type Publisher interface {
	PublishCredential(verifiableCredential vc.VerifiableCredential, public bool) error
	PublishRevocation(revocation credential.Revocation) error
}

type keyResolver interface {
	ResolveAssertionKey(issuerDID did.DID) (crypto.Key, error)
}

// Issuer is a role in the network for a party who issues credentials about a subject to a holder.
type Issuer interface {
	Issue(unsignedCredential vc.VerifiableCredential, publish, public bool) (*vc.VerifiableCredential, error)
	Revoke(credentialID ssi.URI) error
	CredentialResolver() StoreResolver
}

// Store defines the interface for an issuer store.
// An implementation stores all the issued credentials and the revocations.
type Store interface {
	// StoreCredential writes a VC to storage.
	StoreCredential(vc vc.VerifiableCredential, validAt *time.Time) error
	// StoreRevocation writes a revocation to storage.
	StoreRevocation(r credential.Revocation) error
	StoreResolver
}

// StoreResolver defines the functions to resolve or search for credentials.
// It is a separate interface from Store so when an object only needs resolving, it only needs the resolver.
type StoreResolver interface {
	// SearchCredential searches for issued credentials
	SearchCredential(context ssi.URI, credentialType string, issuer did.DID, subject ssi.URI) ([]vc.VerifiableCredential, error)
}
