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

	"github.com/nuts-foundation/nuts-node/vdr/types"

	godid "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"

	"github.com/lestrrat-go/jwx/jwk"
)

var _ types.DIDResolver = (*Resolver)(nil)

// Resolver is a DID resolver for the did:jwk method.
type Resolver struct {}

// NewResolver creates a new Resolver with default TLS configuration.
func NewResolver() *Resolver {
	return &Resolver{}
}

// Resolve implements the DIDResolver interface.
func (w Resolver) Resolve(id did.DID, _ *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	// Ensure this is a did:jwk
	if id.Method != "jwk" {
		return nil, nil, fmt.Errorf("unsupported did method: %s", id.Method)
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

	// Extract the public key from the JWK
	publicRawKey, err := jwk.PublicRawKeyOf(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get PublicRawKeyOf(key): %w", err)
	}

	// Create a new DID verification method.
	// See https://www.w3.org/TR/did-core/#verification-methods	
	verificationMethod, err := did.NewVerificationMethod(id, godid.JsonWebKey2020, id, publicRawKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create verification method: %w", err)
	}

	// Create an empty DID document
	var document did.Document

	// Set the document ID
	newID, err := did.ParseDIDURL("did:jwk:" + b64EncodedJWK)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create document id: %w", err)
	}
	document.ID = *newID

	// Add the verification method
	document.AddAssertionMethod(verificationMethod)

	// Return the newly created document
	return &document, &types.DocumentMetadata{}, nil
}
