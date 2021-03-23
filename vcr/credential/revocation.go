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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"time"
)

// Revocation defines a proof that a VC has been revoked by it's issuer.
type Revocation struct {
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

// BuildRevocation generates a revocation based on the credential
func BuildRevocation(credential vc.VerifiableCredential) Revocation {
	return Revocation{
		Issuer:  credential.Issuer,
		Subject: *credential.ID,
		Date:    nowFunc(),
	}
}

// ValidateRevocation checks if a revocation record contains the required fields and if fields have the correct value.
func ValidateRevocation(r Revocation) error {
	if r.Subject.String() == "" || r.Subject.Fragment == "" {
		return failure("'subject' is required and requires a valid fragment")
	}

	if r.Issuer.String() == "" {
		return failure("'issuer' is required")
	}

	if r.Date.IsZero() {
		return failure("'date' is required")
	}

	if r.Proof == nil {
		return failure("'proof' is required")
	}

	return nil
}
