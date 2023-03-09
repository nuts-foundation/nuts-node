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

package v2

import (
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

// VerifiableCredential is an alias to use from within the API
type VerifiableCredential = vc.VerifiableCredential

// CredentialSubject is an alias to use from within the API
type CredentialSubject = interface{}

// Revocation is an alias to use from within the API
type Revocation = credential.Revocation

// VerifiablePresentation is an alias to use from within the API
type VerifiablePresentation = vc.VerifiablePresentation

// DID is an alias to use from within the API
type DID = did.DID

// SearchVCQuery defines a less strict VerifiableCredential struct without proof which can be used to search for VerifiableCredentials.
// All fields except for the Context are optional
type SearchVCQuery struct {
	// Context defines the json-ld context to dereference the URIs
	Context []ssi.URI `json:"@context"`
	// ID is an unique identifier for the credential. It is optional
	ID *ssi.URI `json:"id,omitempty"`
	// Type holds multiple types for a credential. A credential must always have the 'VerifiableCredential' type.
	Type []ssi.URI `json:"type,omitempty"`
	// Issuer refers to the party that issued the credential
	Issuer *ssi.URI `json:"issuer,omitempty"`
	// IssuanceDate is a rfc3339 formatted datetime.
	IssuanceDate *time.Time `json:"issuanceDate,omitempty"`
	// ExpirationDate is a rfc3339 formatted datetime.
	ExpirationDate *time.Time `json:"expirationDate,omitempty"`
	// CredentialSubject holds the actual data for the credential. It must be extracted using the UnmarshalCredentialSubject method and a custom type.
	CredentialSubject interface{} `json:"credentialSubject,omitempty"`
}

// SearchVCRequest is the request body for searching VCs
type SearchVCRequest struct {
	// A partial VerifiableCredential in JSON-LD format. Each field will be used to match credentials against. All fields MUST be present.
	Query         SearchVCQuery  `json:"query"`
	SearchOptions *SearchOptions `json:"searchOptions,omitempty"`
}
