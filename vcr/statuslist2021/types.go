/*
 * Copyright (C) 2024 Nuts community
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

package statuslist2021

import (
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/jsonld"
)

const (
	// CredentialType is the type of StatusList2021Credential
	CredentialType = "StatusList2021Credential"
	// CredentialSubjectType is the credentialSubject.type in a StatusList2021Credential
	CredentialSubjectType = "StatusList2021"
	// EntryType is the credentialStatus.type that lists the entry of that credential on a list
	EntryType = "StatusList2021Entry"
)

var ContextURI = ssi.MustParseURI(jsonld.W3cStatusList2021Context)
var credentialTypeURI = ssi.MustParseURI(CredentialType)

// Entry is the "credentialStatus" property used by issuers to enable VerifiableCredential status information.
type Entry struct {
	// ID is expected to be a URL that identifies the status information associated with the verifiable credential.
	// It MUST NOT be the URL for the status list, which is in StatusListCredential.
	ID string `json:"id,omitempty"`
	// Type MUST be "StatusList2021Entry"
	Type string `json:"type,omitempty"`
	// StatusPurpose indicates what it means if the VerifiableCredential is on the list.
	// The value is arbitrary, with predefined values `revocation` and `suspension`.
	// This value must match credentialSubject.statusPurpose value in the VerifiableCredential.
	StatusPurpose string `json:"statusPurpose,omitempty"`
	// StatusListIndex is an arbitrary size integer greater than or equal to 0, expressed as a string.
	// The value identifies the bit position of the status of the verifiable credential.
	StatusListIndex string `json:"statusListIndex,omitempty"`
	// The statusListCredential property MUST be a URL to a verifiable credential.
	// When the URL is dereferenced, the resulting verifiable credential MUST have type property that includes the "StatusList2021Credential" value.
	StatusListCredential string `json:"statusListCredential,omitempty"`
}

type CredentialSubject struct {
	// ID for the credential subject
	Id string `json:"id"`
	// Type MUST be "StatusList2021Credential"
	Type string `json:"type"`
	// StatusPurpose defines the reason credentials are listed. ('revocation', 'suspension')
	StatusPurpose string `json:"statusPurpose"`
	// EncodedList is the GZIP-compressed [RFC1952], base-64 encoded [RFC4648] bitstring values for the associated range
	// of verifiable credential status values. The uncompressed bitstring MUST be at least 16KB in size.
	EncodedList string `json:"encodedList"`
}
