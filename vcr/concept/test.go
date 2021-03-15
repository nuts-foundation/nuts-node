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

const ExampleConcept = "human"
const ExampleType = "HumanCredential"

var ExampleTemplate = `
{
	"id": "<<id>>",
	"issuer": "<<issuer>>",
	"type": "HumanCredential@{1_1},{2_1}",
	"credentialSubject": {
		"id": "<<subject>>@{2_2}",
		"human": {
			"eyeColour": "<<human.eyeColour>>@{1_2}",
			"hairColour": "<<human.hairColour>>"
		}
	}
}
`

var TestCredential = `
{
	"id": "did:nuts:1#123",
	"issuer": "did:nuts:1",
	"type": ["VerifiableCredential", "HumanCredential"],
	"credentialSubject": {
		"id": "did:nuts:2",
		"human": {
			"eyeColour": "blue/grey",
			"hairColour": "fair"
		}
	}
}
`

func TestVC() did.VerifiableCredential {
	vc := did.VerifiableCredential{}

	json.Unmarshal([]byte(TestCredential), &vc)

	return vc
}
