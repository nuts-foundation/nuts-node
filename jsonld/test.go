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

// JSONLDExample is a JSON-LD document example with a custom nested context covering all different supported term types.
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

// TestOrganizationCredential is an example of a NutsOrganizationCredential without Proof
const TestOrganizationCredential = `
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://nuts.nl/credentials/v1",
        "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
    ],
    "credentialSubject": {
        "organization": {
            "city": "Caretown",
            "name": "CareBears"
        },
        "id": "did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY"
    },
    "id": "did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H#d2aa8189-db59-4dad-a3e5-60ca54f8fcc0",
    "issuanceDate": "2021-12-24T13:21:29.087205+01:00",
    "expirationDate": "2030-01-01T13:21:29.087205+01:00",
    "issuer": "did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H",
    "proof": {},
    "type": [
        "NutsOrganizationCredential",
        "VerifiableCredential"
    ]
}`

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
	contextConfig.RemoteAllowList = nil
	contextConfig.LocalFileMapping["http://example.org/credentials/V1"] = "test_assets/contexts/test.ldjson"
	contextConfig.LocalFileMapping["https://www.w3.org/2018/credentials/examples/v1"] = "test_assets/contexts/examples.ldjson"
	contextConfig.LocalFileMapping["https://www.w3.org/ns/odrl.jsonld"] = "test_assets/contexts/odrl.ldjson"

	loader := NewMappedDocumentLoader(contextConfig.LocalFileMapping,
		NewEmbeddedFSDocumentLoader(assets.Assets,
			// Handle all embedded file system files
			NewEmbeddedFSDocumentLoader(assets.TestAssets,
				// Last in the chain is the defaultLoader which can resolve
				// local files and remote (via http) context documents
				nil)))

	manager := testContextManager{loader: loader}

	return manager
}
