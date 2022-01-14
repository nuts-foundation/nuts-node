package vcr

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
	keyResolver crypto.KeyStore
}

func (r vdrKeyResolver) ResolveAssertionKey(issuerDID did.DID) (crypto.Key, error) {
	// find did document/metadata for originating TXs
	document, _, err := r.docResolver.Resolve(issuerDID, nil)
	if err != nil {
		return nil, err
	}

	// resolve an assertionMethod key for issuer
	kid, err := doc.ExtractAssertionKeyID(*document)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}

	return r.keyResolver.Resolve(kid.String())
}
