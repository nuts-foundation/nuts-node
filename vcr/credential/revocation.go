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

package credential

import (
	"fmt"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
)

// Revocation defines a proof that a VC has been revoked by its issuer.
type Revocation struct {
	// Context contains the json-ld contexts
	Context []ssi.URI `json:"@context,omitempty"`
	// Type contains the json-ld type, usually this is CredentialRevocation
	Type []ssi.URI `json:"type,omitempty"`
	// Issuer refers to the party that issued the credential
	Issuer ssi.URI `json:"issuer"`
	// Subject refers to the VC that is revoked
	Subject ssi.URI `json:"subject"`
	// Reason describes why the VC has been revoked
	Reason string `json:"reason,omitempty"`
	// Date is a rfc3339 formatted datetime.
	Date time.Time `json:"date"`
	// Proof contains the cryptographic proof(s). It must be extracted using the Proofs method or UnmarshalProofValue method for non-generic proof fields.
	Proof *vc.JSONWebSignature2020Proof `json:"proof,omitempty"`
}

// nowFunc is used to store a function that returns the current time. This can be changed when you want to mock the current time.
var nowFunc = time.Now

// RevocationType contains the JSON-LD type for a revocation
var RevocationType = ssi.MustParseURI("CredentialRevocation")

// BuildRevocation generates a revocation based on the credential
func BuildRevocation(issuer ssi.URI, subject ssi.URI) Revocation {
	nutsCredentialContext := ssi.MustParseURI("https://nuts.nl/credentials/v1")
	return Revocation{
		Context: []ssi.URI{nutsCredentialContext},
		Type:    []ssi.URI{RevocationType},
		Issuer:  issuer,
		Subject: subject,
		Date:    nowFunc(),
	}
}

// ValidateRevocation checks if a revocation record contains the required fields and if fields have the correct value.
func ValidateRevocation(r Revocation) error {
	if r.Subject.String() == "" || r.Subject.Fragment == "" {
		return fmt.Errorf("%w: 'subject' is required and requires a valid fragment", errValidation)
	}

	// Only check type if @context is set
	if len(r.Context) != 0 {
		foundType := false
		for _, val := range r.Type {
			if val == RevocationType {
				foundType = true
				break
			}
		}
		if !foundType {
			return fmt.Errorf("%w: 'type' does not contain %s", errValidation, RevocationType)
		}
	}

	if r.Issuer.String() == "" {
		return fmt.Errorf("%w: 'issuer' is required", errValidation)
	}

	if r.Date.IsZero() {
		return fmt.Errorf("%w: 'date' is required", errValidation)
	}

	if r.Proof == nil {
		return fmt.Errorf("%w: 'proof' is required", errValidation)
	}

	return nil
}
