package vdr

import (
	"crypto"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"time"
)

func (r *VDR) ResolveSigningKeyID(holder did.DID, validAt *time.Time) (string, error) {
	doc, _, err := r.Resolve(holder, &types.ResolveMetadata{
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
		return "", types.ErrKeyNotFound
	}
	return result.PublicKey()
}

func (r *VDR) ResolveAssertionKey(id did.DID) (ssi.URI, error) {
	doc, _, err := r.Resolve(id, nil)
	if err != nil {
		return ssi.URI{}, err
	}

	keys := doc.AssertionMethod
	for _, key := range keys {
		kid := key.ID.String()
		if r.keyStore.PrivateKeyExists(kid) {
			u, _ := ssi.ParseURI(kid)
			return *u, nil
		}
	}

	return ssi.URI{}, types.ErrKeyNotFound
}
