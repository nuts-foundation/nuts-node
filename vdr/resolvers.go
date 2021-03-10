package vdr

import (
	"crypto"
	"fmt"
<<<<<<< HEAD
=======
	"net/url"
>>>>>>> master
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"hash/crc32"
)

// NameResolver defines functions for resolving the name of an entity holding a DID.
type NameResolver interface {
	// Resolve resolves the name of a DID holder.
	Resolve(input did.DID) (string, error)
}

// NewDummyNameResolver returns a NameResolver that generates a name based on the DID.
// TODO: Remove this after implementing VCs (https://github.com/nuts-foundation/nuts-node/issues/90)
func NewDummyNameResolver() NameResolver {
	return &dummyNameResolver{}
}

type dummyNameResolver struct {
}

func (d dummyNameResolver) Resolve(input did.DID) (string, error) {
	return fmt.Sprintf("Company #%d", crc32.ChecksumIEEE([]byte(input.String()))%1000), nil
}

func (r *VDR) ResolveSigningKeyID(holder did.DID, validAt *time.Time) (string, error) {
	doc, _, err := r.Resolve(holder, &types.ResolveMetadata{
		ResolveTime: validAt,
	})
	if err != nil {
		return "", err
	}
	if len(doc.AssertionMethod) == 0 {
		return "", fmt.Errorf("DID Document has no assertionMethod keys (did=%s)", holder)
	}
	return doc.AssertionMethod[0].ID.String(), nil
}

func (r *VDR) ResolveSigningKey(keyID string, validAt *time.Time) (crypto.PublicKey, error) {
	kid, err := did.ParseDID(keyID)
	if err != nil {
		return nil, fmt.Errorf("invalid key ID (id=%s): %w", keyID, err)
	}
	holder := *kid
	holder.Fragment = ""
	doc, _, err := r.Resolve(holder, &types.ResolveMetadata{
		ResolveTime: validAt,
	})
	if err != nil {
		return "", err
	}
	var result *did.VerificationRelationship
	for _, rel := range doc.AssertionMethod {
		if rel.ID.String() == keyID {
			result = &rel
		}
	}
	if result == nil {
		return "", fmt.Errorf("signing key not found (id=%s)", keyID)
	}
	return result.PublicKey()
}

func (r *VDR) ResolveAssertionKey(id did.DID) (did.URI, error) {
	doc, _, err := r.Resolve(id, nil)
	if err != nil {
		return did.URI{}, err
	}

	keys := doc.AssertionMethod
	for _, key := range keys {
		kid := key.ID.String()
		if r.keyStore.PrivateKeyExists(kid) {
<<<<<<< HEAD
			u, _ := did.ParseURI(kid)
			return *u, nil
=======
			u, _ := url.Parse(kid)
			return did.URI{URL: *u}, nil
>>>>>>> master
		}
	}

	return did.URI{}, fmt.Errorf("no valid assertion keys found for: %s", id.String())
}
