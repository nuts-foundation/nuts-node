/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package resolver

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"sort"
	"strings"
	"time"
)

// ErrKeyNotFound is returned when a particular key or type of key is not found.
var ErrKeyNotFound = errors.New("key not found in DID document")

// NutsSigningKeyType defines the verification method relationship type for signing keys in Nuts DID Documents.
const NutsSigningKeyType = AssertionMethod

// KeyResolver is the interface for resolving keys.
// This can be used for checking if a signing key is valid at a point in time or to just find a valid key for signing.
type KeyResolver interface {
	// ResolveKeyByID looks up a specific key of the given RelationType and returns it as crypto.PublicKey.
	// If multiple keys are valid, the first one is returned.
	// An ErrKeyNotFound is returned when no key (of the specified type) is found.
	ResolveKeyByID(keyID string, validAt *time.Time, relationType RelationType) (crypto.PublicKey, error)
	// ResolveKey looks for a valid key of the given RelationType for the given DID, and returns its ID and the key itself.
	// If multiple keys are valid, the first one is returned.
	// An ErrKeyNotFound is returned when no key (of the specified type) is found.
	ResolveKey(id did.DID, validAt *time.Time, relationType RelationType) (ssi.URI, crypto.PublicKey, error)
}

// NutsKeyResolver is the interface for resolving keys from Nuts DID Documents,
// supporting Nuts-specific DID resolution parameters.
type NutsKeyResolver interface {
	// ResolvePublicKey loads the key from a DID Document where the DID Document
	// was created with one of the given tx refs
	// It returns ErrKeyNotFound when the key could not be found in the DID Document.
	// It returns ErrNotFound when the DID Document can't be found.
	ResolvePublicKey(kid string, sourceTransactionsRefs []hash.SHA256Hash) (crypto.PublicKey, error)
}

var _ KeyResolver = DIDKeyResolver{}

// DIDKeyResolver implements the DIDKeyResolver interface that uses keys from resolved DIDs.
type DIDKeyResolver struct {
	Resolver DIDResolver
}

func (r DIDKeyResolver) ResolveKeyByID(keyID string, validAt *time.Time, relationType RelationType) (crypto.PublicKey, error) {
	holder, err := GetDIDFromURL(keyID)
	if err != nil {
		return nil, fmt.Errorf("invalid key ID (id=%s): %w", keyID, err)
	}
	doc, _, err := r.Resolver.Resolve(holder, &ResolveMetadata{
		ResolveTime: validAt,
	})
	if err != nil {
		return nil, err
	}
	relationships, err := resolveRelationships(doc, relationType)
	if err != nil {
		return nil, err
	}
	for _, rel := range relationships {
		if rel.ID.String() == keyID {
			return rel.PublicKey()
		}
	}
	return nil, ErrKeyNotFound
}

func (r DIDKeyResolver) ResolveKey(id did.DID, validAt *time.Time, relationType RelationType) (ssi.URI, crypto.PublicKey, error) {
	keys, err := resolveKeys(r.Resolver, id, validAt, relationType)
	if err != nil {
		return ssi.URI{}, nil, err
	}
	if len(keys) == 0 {
		return ssi.URI{}, nil, ErrKeyNotFound
	}
	publicKey, err := keys[0].PublicKey()
	if err != nil {
		return ssi.URI{}, nil, err
	}
	return keys[0].ID.URI(), publicKey, nil
}

// PrivateKeyResolver resolves private keys based upon the VDR document resolver
type PrivateKeyResolver struct {
	DIDResolver     DIDResolver
	PrivKeyResolver nutsCrypto.KeyResolver
}

// ResolvePrivateKey is a tries to find a private key in the node's keystore for the given DID, of the given type.
// Special treatment is given to did:web DIDs, which are assumed to be a derivative of a did:nuts DID:
// It will try to return a private key from the did:nuts document, as long as it's present (given it's public key fingerprint)
// in the did:web document (since the caller requested a did:web key, not a did:nuts one).
// If no private key is found, ErrKeyNotFound is returned.
func (r PrivateKeyResolver) ResolvePrivateKey(ctx context.Context, id did.DID, validAt *time.Time, relationType RelationType) (nutsCrypto.Key, error) {
	keys, err := resolveKeys(r.DIDResolver, id, validAt, relationType)
	if err != nil {
		return nil, err
	}
	// Optimization: give precedence to did:nuts keys, since those are most likely to be present (in contrary to did:web)
	// Sort keys by DID method, so did:nuts keys are first
	sort.SliceStable(keys, func(i, j int) bool {
		if keys[i].ID.Method == "nuts" {
			return true
		}
		return false
	})
	for _, key := range keys {

		var keyID did.DID
		if strings.HasPrefix(key.ID.String(), "#") {
			// fragment-only key, refers controller DID
			keyID = key.Controller
			keyID.Fragment = keyID.Fragment
		} else {
			keyID = key.ID
		}
		privateKey, err := r.PrivKeyResolver.Resolve(ctx, keyID.String())
		if err != nil {
			if errors.Is(err, nutsCrypto.ErrPrivateKeyNotFound) {
				continue
			}
			return nil, fmt.Errorf("failed to resolve private key (kid=%s): %w", key.ID, err)
		}
		if id.Method == "web" && key.ID.Method == "nuts" {
			// did:web is a derivative of did:nuts, match with key on did:web method since it's an alias of the did:nuts key.
			for _, candidate := range keys {
				if candidate.ID.WithoutURL().Equals(id) && // check it's a key from the requested DID
					candidate.PublicKeyBase58 == key.PublicKeyBase58 {
					return nutsCrypto.Alias(privateKey, candidate.ID.String()), nil
				}
			}
		}
		// Otherwise, just return the key
		return privateKey, nil
	}
	// No keys were found
	return nil, ErrKeyNotFound
}

func resolveKeys(didResolver DIDResolver, id did.DID, validAt *time.Time, relationType RelationType) ([]did.VerificationRelationship, error) {
	var docs []*did.Document
	doc, _, err := didResolver.Resolve(id, &ResolveMetadata{
		ResolveTime: validAt,
	})
	if err != nil {
		return nil, err
	}
	docs = append(docs, doc)
	// did:web of a Nuts node is probably a derivative of a did:nuts to which it refers to using alsoKnownAs,
	// so if that's the case we need to resolve those as well, since the keys are stored under their did:nuts ID, not did:web.
	if doc.ID.Method == "web" && len(doc.AlsoKnownAs) > 0 {
		for _, aka := range doc.AlsoKnownAs {
			akaDID, _ := did.ParseDID(aka.String())
			if akaDID == nil {
				// alsoKnownAs is not a DID
				continue
			}
			if akaDID.Method != "nuts" {
				// Just to be sure, only support did:nuts alsoKnownAs for now. Otherwise, we might end up in an infinite loop?
				continue
			}
			akaDoc, _, err := didResolver.Resolve(*akaDID, &ResolveMetadata{ResolveTime: validAt, AllowDeactivated: false})
			if err != nil && !IsFunctionalResolveError(err) {
				// Ignore unresolvable alsoKnownAs documents
				return nil, fmt.Errorf("failed to resolve alsoKnownAs (did=%s, alsoKnownAs=%s): %w", id, akaDID, err)
			}
			if akaDoc != nil {
				docs = append(docs, akaDoc)
			}
		}
	}
	var allKeys []did.VerificationRelationship
	for _, doc := range docs {
		docKeys, err := resolveRelationships(doc, relationType)
		if err != nil {
			return nil, err
		}
		allKeys = append(allKeys, docKeys...)
	}
	return allKeys, nil
}

func resolveRelationships(doc *did.Document, relationType RelationType) (relationships did.VerificationRelationships, err error) {
	switch relationType {
	case Authentication:
		return doc.Authentication, nil
	case AssertionMethod:
		return doc.AssertionMethod, nil
	case KeyAgreement:
		return doc.KeyAgreement, nil
	case CapabilityInvocation:
		return doc.CapabilityInvocation, nil
	case CapabilityDelegation:
		return doc.CapabilityDelegation, nil
	default:
		return nil, fmt.Errorf("unable to locate RelationType %v", relationType)
	}
}

// RelationType is the type that contains the different possible relationships between a DID Document and a VerificationMethod
// They are defined in the DID spec: https://www.w3.org/TR/did-core/#verification-relationships
type RelationType uint

const (
	Authentication       RelationType = iota
	AssertionMethod      RelationType = iota
	KeyAgreement         RelationType = iota
	CapabilityInvocation RelationType = iota
	CapabilityDelegation RelationType = iota
)
