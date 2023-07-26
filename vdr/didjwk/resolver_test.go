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
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolver_Resolve(t *testing.T) {
	// Allocate a DID JWK resolver
	resolver := &Resolver{}

	// Define a test generator for successful resolution
	success := func(id string) func(t *testing.T) {
		return func(t *testing.T) {
			// Parse the DID using the provided ID
			baseDID := did.MustParseDID("did:jwk:" + id)

			// Resolve the DID
			doc, metadata, err := resolver.Resolve(baseDID, nil)

			// Ensure no error was returned
			require.NoError(t, err)

			// Ensure the metadata was returned
			assert.NotNil(t, metadata)

			// Ensure the DID document was returned
			require.NotNil(t, doc)

			// Ensure the DID document has the correct ID
			assert.Equal(t, baseDID, doc.ID)
		}
	}

	// Use a utility function for encoding strings to base 64 strings
	b64 := func(s string) string {
		return base64.RawStdEncoding.EncodeToString([]byte(s))
	}

	// Ensure the canonical example from the DID JWK spec can be resolved
	t.Run("resolve did:jwk", success(b64(canonicalJWK)))

	// Ensure the DID JWK with the fixed '#0' fragment can be resolved
	// TODO: Much confusion here
	//t.Run("resolve did:jwk URL (with fragment)", success(b64(canonicalJWK) + "#0"))

	// Test the various failure modes of resolution
	t.Run("resolution errors", func(t *testing.T) {
		// Define a test function generator
		failure := func(id string, msg string) func(t *testing.T) {
			// Generate a test function using the specified JWK JSON string
			return func(t *testing.T) {
				// Parse the DID
				id := did.MustParseDIDURL("did:jwk:" + id)

				// Resolve the DID, which returns a document/error
				doc, md, err := resolver.Resolve(id, nil)

				// Ensure the resolution failed with the appropriate error message
				require.ErrorContains(t, err, msg)

				// Ensure a document and metadata were not returned
				assert.Nil(t, md)
				assert.Nil(t, doc)
			}
		}

		// Ensure invalid base64 DID fails
		t.Run("Invalid base64 data fails", failure(b64(canonicalJWK) + ":invalid-base64-data", "illegal base64 data at input"))

		// Ensure a DID with invalid JSON fails
		t.Run("base64 encoded non-JSON fails", failure("!@#__NOT JSON__#@!", "failed to unmarshal JSON"))

		// Ensure valid JSON as an invalid JWK fails
		t.Run("base64+JSON encoded non-JWK fails", failure(validJSONInvalidJWK, "invalid key type from JSON"))

		// Ensure resolution fails when a DID JWK contains a private key
		t.Run("DID JWK with private key fails", func(t *testing.T) {
			// Parsing a DID JWK containing a private key should result in this error
			msg := "private keys are forbidden in DID JWK"

			// Test various private key types
			t.Run("RSA2048", failure(b64(rsa2048JWKWithPrivateKey), msg))
			t.Run("RSA4096", failure(b64(rsa4096JWKWithPrivateKey), msg))
			t.Run("EC256", failure(b64(ec256JWKWithPrivateKey), msg))
			t.Run("EC384", failure(b64(ec384JWKWithPrivateKey), msg))
			t.Run("EC512", failure(b64(ec521JWKWithPrivateKey), msg))
			t.Run("Ed25519", failure(b64(ed25519JWKWithPrivateKey), msg))
			t.Run("X25519", failure(b64(x25519JWKWithPrivateKey), msg))
		})
	})
}
