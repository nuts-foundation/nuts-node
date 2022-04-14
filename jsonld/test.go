/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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

package jsonld

import (
	"encoding/json"
	"testing"

	"github.com/nuts-foundation/nuts-node/vcr/assets"
	"github.com/piprate/json-gold/ld"

	"github.com/nuts-foundation/go-did/vc"
)

const JSONLDExample = `
{
  "@context": {
    "id": "@id",
    "type": "@type",
    "schema": "http://example.com/",
    "Person": {
      "@id": "schema:Person",
      "@context": {
        "id": "@id",
        "type": "@type",
        "name": {"@id": "schema:name"},
        "telephone": {"@id": "schema:telephone", "@container": "@list"},
        "url": {"@id": "schema:url", "@type": "@id"},
        "children": {"@id": "schema:children", "@container": "@list"},
		"parents": {"@id": "schema:parents"}
      }
    }
  },
  "@type": "Person",
  "@id": "123456782",
  "name": "Jane Doe",
  "url": "http://www.janedoe.com",
  "telephone": ["06-12345678", "06-87654321"],
  "children": [{
    "@type": "Person",
    "name": "John Doe",
	"url": "http://www.johndoe.org"
  }],
  "parents": [{
    "@type": "Person",
    "name": "John Doe",
	"url": "http://www.johndoe.org"
  }]
}
`

// invalidJSONLD contains an incorrect version for JSON-LD
const invalidJSONLD = `
{
  "@context": [
    {
      "@version": 0.1
    }
  ]
}
`

// TestCredential contains a valid credential of the Humancredential type
const TestCredential = `
{
	"@context": [
		"https://www.w3.org/2018/credentials/v1",
		"http://example.org/credentials/V1"
	  ],
	"id": "did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY#123",
	"issuer": "did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY",
	"issuanceDate": "1970-01-01T12:00:00Z",
	"expirationDate": "2030-01-01T12:00:00Z",
	"type": ["VerifiableCredential", "HumanCredential"],
	"credentialSubject": {
		"id": "did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW",
		"human": {
			"eyeColour": "blue/grey",
			"hairColour": "fair"
		}
	},
	"proof": {}
}
`

// TestVC returns an instance of the TestCredential
func TestVC() vc.VerifiableCredential {
	credential := vc.VerifiableCredential{}

	json.Unmarshal([]byte(TestCredential), &credential)

	return credential
}

type testContextManager struct {
	loader ld.DocumentLoader
}

func (t testContextManager) DocumentLoader() ld.DocumentLoader {
	return t.loader
}

func (t testContextManager) Configure(config Config) error {
	//TODO implement me
	panic("implement me")
}

// NewTestJSONLDManager creates a new test context manager which contains extra test contexts
func NewTestJSONLDManager(t *testing.T) JSONLD {
	t.Helper()

	contextConfig := DefaultContextConfig()
	contextConfig.LocalFileMapping["http://example.org/credentials/V1"] = "test_assets/contexts/test.ldjson"

	loader := NewMappedDocumentLoader(contextConfig.LocalFileMapping,
		NewEmbeddedFSDocumentLoader(assets.Assets,
			// Handle all embedded file system files
			NewEmbeddedFSDocumentLoader(assets.TestAssets,
				// Last in the chain is the defaultLoader which can resolve
				// local files and remote (via http) context documents
				ld.NewDefaultDocumentLoader(nil))))

	manager := testContextManager{loader: loader}

	return manager
}
