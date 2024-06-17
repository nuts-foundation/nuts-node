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
	"crypto"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"reflect"
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
	baseUrl := r.baseUrl(doc)
	relationships, err := resolveRelationships(doc, relationType)
	if err != nil {
		return nil, err
	}
	for _, rel := range relationships {
		localKeyId := rel.ID.String()
		if localKeyId == keyID {
			return rel.PublicKey()
		} else if baseUrl != nil && strings.HasPrefix(localKeyId, "#") {
			localKeyId = *baseUrl + localKeyId
			if localKeyId == keyID {
				return rel.PublicKey()
			}
		}
	}
	return nil, ErrKeyNotFound
}

// baseUrl returns the base URL of the given DID Document.
// It searches for the "@base" field in the DID Document's context.
// If the context is a map and contains the "@base" field, it returns the value of "@base".
// If the context does not contain the "@base" field, it returns nil.
func (r DIDKeyResolver) baseUrl(doc *did.Document) (baseUrl *string) {
	context := doc.Context
	for i := range context {
		ctx := context[i]
		if reflect.ValueOf(ctx).Kind() == reflect.Map {
			m := ctx.(map[string]interface{})
			if val, ok := m["@base"]; ok {
				valStr := val.(string)
				baseUrl = &valStr
				break
			}

		}
	}
	return baseUrl
}

func (r DIDKeyResolver) ResolveKey(id did.DID, validAt *time.Time, relationType RelationType) (ssi.URI, crypto.PublicKey, error) {
	// todo use sql DB to select key
	doc, _, err := r.Resolver.Resolve(id, &ResolveMetadata{
		ResolveTime: validAt,
	})
	if err != nil {
		return ssi.URI{}, nil, err
	}
	keys, err := resolveRelationships(doc, relationType)
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
