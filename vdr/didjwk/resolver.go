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

package didjwk

import (
	"encoding/base64"
	"fmt"
	"reflect"

	"github.com/nuts-foundation/nuts-node/vdr/types"

	godid "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"

	"github.com/lestrrat-go/jwx/jwk"
)

var _ types.DIDResolver = (*Resolver)(nil)

// Resolver is a DID resolver for the did:jwk method.
type Resolver struct{}

// NewResolver creates a new Resolver with default TLS configuration.
func NewResolver() *Resolver {
	return &Resolver{}
}

// Resolve implements the DIDResolver interface.
func (w Resolver) Resolve(id did.DID, _ *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	// Ensure this is a did:jwk
	if id.Method != "jwk" {
		return nil, nil, fmt.Errorf("unsupported DID method: %s", id.Method)
	}

	// Get the third section of the did, e.g. "did:jwk:..."
	b64EncodedJWK := id.ID

	// Decode the base64 to JWK
	encodedJWK, err := base64.RawStdEncoding.DecodeString(b64EncodedJWK)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base64 (%v): %w", b64EncodedJWK, err)
	}

	// Parse the JWK
	key, err := jwk.ParseKey(encodedJWK)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	// Reject any DID JWK containing a private key
	rawPrivateKey, err := rawPrivateKeyOf(key)
	if err != nil {
		return nil, nil, fmt.Errorf("rawPrivateKeyOf() failed: %w", err)
	}
	if rawPrivateKey != nil {
		return nil, nil, fmt.Errorf("private keys are forbidden in DID JWK: %T", rawPrivateKey)
	}

	// Extract the public key from the JWK
	publicRawKey, err := jwk.PublicRawKeyOf(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get PublicRawKeyOf(key): %w", err)
	}

	// Create a new DID verification method.
	// See https://www.w3.org/TR/did-core/#verification-methods
	keyID := id.WithoutURL()
	keyID.Fragment = "0"
	verificationMethod, err := did.NewVerificationMethod(keyID, godid.JsonWebKey2020, id.WithoutURL(), publicRawKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create verification method: %w", err)
	}

	// Create an empty DID document
	var document did.Document

	// Set the document ID
	document.ID = id.WithoutURL()

	// Add the verification method
	document.AddAssertionMethod(verificationMethod)

	// Return the newly created document
	return &document, &types.DocumentMetadata{}, nil
}

// rawPrivateKeyOf returns the private key component of a jwk.Key, or nil if one is not available (e.g. public key only JWK's). An error is returned if a public key is not contained in the JWK. This is more tricky than it might seem at first
// as a JWK can contain either a private/public keypair or a public key and therefore must be inspected carefully to
// determine the type of raw keys being returned. This function is intended to work in a generic manner with any type of
// asymmetric key and therefore the implementation is trickier yet compared to logic about specific key algorithms.
//
// Caution: This function uses reflection which may impact performance.
func rawPrivateKeyOf(key jwk.Key) (any, error) {
	// Get the raw key value, which is a golang crypto primitive, and possibly a private key. In order to determine
	// wether this is a private or public key more work is required. We could inspect the concrete type of the key
	// but that would require adding code about specific key algorithms and could break down as new key algorithms
	// are introduced, requiring careful maintenance. Instead a generic approach will be taken where we compare the
	// any known public key contained in the JWK to the rawUnspecifiedKey and determine whether a second (private)
	// value is available. If the jwx/jwk library offers a way in the future to specifically get a private key from
	// a JWK this will be much simpler.
	var rawUnspecifiedKey any
	if err := key.Raw(&rawUnspecifiedKey); err != nil {
		return nil, fmt.Errorf("failed to get raw key: %w", err)
	}

	// Get the public key value, which is also a jwk.Key. The PublicKeyOf() result is needed in order to compare
	// to rawUnspecifiedKey and determine whether a private key is contained within the JWK. This makes more sense
	// later in the function, but looks strange here since the goal of this function is to get the private key.
	publicKey, err := jwk.PublicKeyOf(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Get the raw public key, which is a golang crypto primitive, or nil. This will be compared next to the
	// rawUnspecifiedKey (unspecified as public or private) key to determine whether a private key can be returned.
	var rawPublicKey any
	if err := publicKey.Raw(&rawPublicKey); err != nil {
		return nil, fmt.Errorf("failed to get raw public key: %w", err)
	}

	// If rawUnspecifiedKey and rawPublicKey are the same then there is no private key to return. This can occur
	// since a JWK can contain either a public/private keypair or simply a public key.
	if reflect.DeepEqual(rawUnspecifiedKey, rawPublicKey) {
		// The key.Raw() result was the same as the PublicKeyOf(key).Raw() result, which indicates that
		// no private key is contained in this JWK and therefore we cannot return any private key. If
		// this function is intended to be used in a more general purpose way it might make sense to
		// return an error here, but for the purpose of DID JWK that isn't useful.
		return nil, nil
	}

	// As rawUnspecifiedKey and rawPublicKey are not the same we have a private key to return
	return rawUnspecifiedKey, nil
}
