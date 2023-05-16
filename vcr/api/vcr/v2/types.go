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
	"encoding/json"
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

var _ json.Marshaler = (*IssueVC200JSONResponse)(nil)
var _ json.Marshaler = (*ResolveVC200JSONResponse)(nil)
var _ json.Marshaler = (*CreateVP200JSONResponse)(nil)

// MarshalJSON forwards the call to the underlying VerifiableCredential to make sure the expected JSON-LD is returned.
func (r IssueVC200JSONResponse) MarshalJSON() ([]byte, error) {
	return vc.VerifiableCredential(r).MarshalJSON()
}

// MarshalJSON forwards the call to the underlying VerifiableCredential to make sure the expected JSON-LD is returned.
func (r ResolveVC200JSONResponse) MarshalJSON() ([]byte, error) {
	return vc.VerifiableCredential(r).MarshalJSON()
}

// MarshalJSON forwards the call to the underlying VerifiableCredential to make sure the expected JSON-LD is returned.
func (r CreateVP200JSONResponse) MarshalJSON() ([]byte, error) {
	return vc.VerifiablePresentation(r).MarshalJSON()
}
