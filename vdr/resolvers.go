package vdr

import (
	"crypto"
	"fmt"
	"hash/crc32"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"

	"github.com/nuts-foundation/nuts-node/vdr/types"
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

type VDRKeyResolver struct {
	VDR types.VDR
// KeyResolver implements the KeyResolver interface with a DocResolver as backend
}

func (r VDRKeyResolver) ResolveSigningKeyID(holder did.DID, validAt *time.Time) (string, error) {
	doc, _, err := r.VDR.Resolve(holder, &types.ResolveMetadata{
// ResolveSigningKeyID resolves the ID of the first valid AssertionMethod for a indicated DID document at a given time.
		ResolveTime: validAt,
	})
	if err != nil {
		return "", err
	}
	if len(doc.AssertionMethod) == 0 {
		return "", types.ErrKeyNotFound
	}
	return doc.AssertionMethod[0].ID.String(), nil
}

func (r VDRKeyResolver) ResolveSigningKey(keyID string, validAt *time.Time) (crypto.PublicKey, error) {
// ResolveSigningKey resolves the PublicKey of the first valid AssertionMethod for an indicated
// DID document at a validAt time.
	kid, err := did.ParseDID(keyID)
	if err != nil {
		return nil, fmt.Errorf("invalid key ID (id=%s): %w", keyID, err)
	}
	holder := *kid
	holder.Fragment = ""
	doc, _, err := r.VDR.Resolve(holder, &types.ResolveMetadata{
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
		return "", types.ErrKeyNotFound
	}
	return result.PublicKey()
}

func (r VDRKeyResolver) ResolveAssertionKeyID(id did.DID) (ssi.URI, error) {
	doc, _, err := r.VDR.Resolve(id, nil)
// ResolveAssertionKeyID resolves the id of the first valid AssertionMethod of an indicated DID document in the current state.
	if err != nil {
		return ssi.URI{}, err
	}
	keys := doc.AssertionMethod
	for _, key := range keys {
		kid := key.ID.String()
		u, _ := ssi.ParseURI(kid)
		return *u, nil
	}

	return ssi.URI{}, types.ErrKeyNotFound
}
