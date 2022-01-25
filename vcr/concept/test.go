/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

package concept

import (
	"encoding/json"

	"github.com/nuts-foundation/go-did/vc"
)

const ExampleConcept = "human"
const ExampleType = "HumanCredential"

var humanEyeColour = "human.eyeColour"
var humanHairColour = "human.hairColour"
var humanSubject = "subject"
var humanTemplate = `
{
	"id": "<<id>>",
	"issuer": "<<issuer>>",
	"type": "HumanCredential",
	"subject": "<<credentialSubject.id>>",
	"human": {
		"eyeColour": "<<credentialSubject.human.eyeColour>>",
		"hairColour": "<<credentialSubject.human.hairColour>>"
	}
}
`
var ExampleConfig = Config{
	Concept:        "human",
	CredentialType: "HumanCredential",
	Indices: []Index{
		{
			Name: "human",
			Parts: []IndexPart{
				{Alias: &humanEyeColour, JSONPath: "credentialSubject.human.eyeColour"},
				{Alias: &humanHairColour, JSONPath: "credentialSubject.human.hairColour"},
			},
		},
		{
			Name:  "subject",
			Parts: []IndexPart{{Alias: &humanSubject, JSONPath: "credentialSubject.id"}},
		},
		{
			Name:  "id",
			Parts: []IndexPart{{JSONPath: "id"}},
		},
		{
			Name:  "issuer",
			Parts: []IndexPart{{JSONPath: "issuer"}},
		},
	},
	Template: &humanTemplate,
}

const TestCredential = `
{
	"@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://nuts.nl/credentials/v1"
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

const TestRevocation = `
{
  "issuer": "did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY",
  "subject": "did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY#123",
  "currentStatus": "Revoked",
  "statusDate": "2021-03-13T16:39:58.496215+01:00"
}
`

func TestVC() vc.VerifiableCredential {
	credential := vc.VerifiableCredential{}

	json.Unmarshal([]byte(TestCredential), &credential)

	return credential
}
