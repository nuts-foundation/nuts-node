package vdr

import (
	"crypto"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"hash/crc32"
	"time"
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

type DocumentKeyResolver struct {
	Document did.Document
}

type VDRKeyResolver struct {
	VDR types.VDR
}

func (d DocumentKeyResolver) ResolveSigningKeyID(holder did.DID, validAt *time.Time) (string, error) {
	if len(d.Document.AssertionMethod) == 0 {
		return "", types.ErrKeyNotFound
	}
	return d.Document.AssertionMethod[0].ID.String(), nil
}

func (d DocumentKeyResolver) ResolveSigningKey(keyID string, validAt *time.Time) (crypto.PublicKey, error) {
	var result *did.VerificationRelationship
	for _, rel := range d.Document.AssertionMethod {
		if rel.ID.String() == keyID {
			result = &rel
		}
	}
	if result == nil {
		return "", types.ErrKeyNotFound
	}
	return result.PublicKey()
}

func (d DocumentKeyResolver) ResolveAssertionKeyID(id did.DID) (ssi.URI, error) {
	if !d.Document.ID.Equals(id) {
		return ssi.URI{}, errors.New("provided id does not match resolver DID document")
	}
	keys := d.Document.AssertionMethod
	for _, key := range keys {
		kid := key.ID.String()
		u, _ := ssi.ParseURI(kid)
		return *u, nil
	}

	return ssi.URI{}, types.ErrKeyNotFound
}

func (r VDRKeyResolver) ResolveSigningKeyID(holder did.DID, validAt *time.Time) (string, error) {
	doc, _, err := r.VDR.Resolve(holder, &types.ResolveMetadata{
		ResolveTime: validAt,
	})
	if err != nil {
		return "", err
	}
	return DocumentKeyResolver{Document: *doc}.ResolveSigningKeyID(holder, validAt)
}

func (r VDRKeyResolver) ResolveSigningKey(keyID string, validAt *time.Time) (crypto.PublicKey, error) {
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
	return DocumentKeyResolver{
		Document: *doc,
	}.ResolveSigningKey(keyID, validAt)
}

func (r VDRKeyResolver) ResolveAssertionKeyID(id did.DID) (ssi.URI, error) {
	doc, _, err := r.VDR.Resolve(id, nil)
	if err != nil {
		return ssi.URI{}, err
	}
	return DocumentKeyResolver{Document: *doc}.ResolveAssertionKeyID(id)
}
