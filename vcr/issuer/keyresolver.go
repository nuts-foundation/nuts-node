package issuer

import (
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

// vdrKeyResolver resolves private keys based upon the VDR document resolver
type vdrKeyResolver struct {
	docResolver vdr.DocResolver
	keyResolver crypto.KeyResolver
}

// ResolveAssertionKey is a convenience method which tries to find a assertionKey on in the VDR for a given issuerDID.
func (r vdrKeyResolver) ResolveAssertionKey(issuerDID did.DID) (crypto.Key, error) {
	// find did document/metadata for originating TXs
	document, _, err := r.docResolver.Resolve(issuerDID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve assertionKey: could not resolve did document is vdr: %w", err)
	}

	// resolve an assertionMethod key for issuer
	kid, err := doc.ExtractAssertionKeyID(*document)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}

	key, err := r.keyResolver.Resolve(kid.String())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve assertionKey: could not resolve key from keyStore: %w", err)
	}

	return key, err
}
