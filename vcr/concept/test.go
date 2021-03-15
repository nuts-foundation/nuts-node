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

	"github.com/nuts-foundation/go-did"
)

const ExampleConcept = "company"
const ExampleType = "ExampleCredential"

var ExampleTemplate = `
{
	"id": "<<id>>",
	"issuer": "<<issuer>>",
	"type": "ExampleCredential@{1_1},{2_1}",
	"credentialSubject": {
		"id": "<<subject>>@{2_2}",
		"company": {
			"name": "<<company.name>>@{1_2}",
			"city": "<<company.city>>"
		}
	}
}
`

var TestCredential = `
{
	"id": "did:nuts:1#123",
	"issuer": "did:nuts:1",
	"type": ["VerifiableCredential", "ExampleCredential"],
	"credentialSubject": {
		"id": "did:nuts:2",
		"company": {
			"name": "Because we care BV",
			"city": "Eibergen"
		}
	}
}
`

var TestRevocation = `
{
  "issuer": "did:nuts:1",
  "subject": "did:nuts:1#123",
  "currentStatus": "Revoked",
  "statusDate": "2021-03-13T16:39:58.496215+01:00"
}
`

func TestVC() did.VerifiableCredential {
	vc := did.VerifiableCredential{}

	json.Unmarshal([]byte(TestCredential), &vc)

	return vc
}
