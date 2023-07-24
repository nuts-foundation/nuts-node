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

package pe

import (
	"encoding/json"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

const testPresentationDefinition = `
{
  "id": "Definition requesting NutsOrganizationCredential",
  "input_descriptors": [
	{
	  "id": "some random ID",
	  "name": "Organization matcher",
	  "purpose": "Finding any organization in CareTown starting with 'Care'",
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.credentialSubject.organization.city"
			],
			"filter": {
			  "type": "string",
			  "const": "Caretown"
			}
		  },
		  {
			"path": [
			  "$.credentialSubject.organization.name"
			],
			"filter": {
			  "type": "string",
			  "pattern": "Care"
			}
		  },
		  {
			"path": [
			  "$.type"
			],
			"filter": {
			  "type": "string",
			  "const": "NutsOrganizationCredential"
			}
		  }
		]
	  }
	}
  ]
}
`

func TestMatch(t *testing.T) {
	presentationDefinition := PresentationDefinition{}
	_ = json.Unmarshal([]byte(testPresentationDefinition), &presentationDefinition)
	verifiableCredential := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestOrganizationCredential), &verifiableCredential)

	presentationSubmission, vcs, err := Match(presentationDefinition, []vc.VerifiableCredential{verifiableCredential})

	require.NoError(t, err)
	assert.Len(t, vcs, 1)
	assert.Len(t, presentationSubmission.DescriptorMap, 1)
}
