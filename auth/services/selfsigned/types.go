/*
 * Nuts node
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
 */

package selfsigned

import (
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

// ContractFormat is the contract format type
const ContractFormat = "selfsigned"

// VerifiablePresentationType is the dummy verifiable presentation type
const VerifiablePresentationType = "NutsSelfSignedPresentation"

type sessionPointer struct {
	sessionID string
	url       string
}

func (s sessionPointer) SessionID() string {
	return s.sessionID
}

func (s sessionPointer) Payload() []byte {
	return []byte(s.url)
}

func (s sessionPointer) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SessionID string `json:"sessionID"`
		Page      string `json:"url"`
	}{SessionID: s.sessionID, Page: s.url})
}

type signingSessionResult struct {
	id                     string
	status                 string
	request                string
	verifiablePresentation *vc.VerifiablePresentation
}

func (s signingSessionResult) Status() string {
	return s.status
}

func (s signingSessionResult) VerifiablePresentation() (*vc.VerifiablePresentation, error) {
	return s.verifiablePresentation, nil
}

type employeeIdentityCredentialSubject struct {
	credential.BaseCredentialSubject                                  // ID
	Type                             string                           `json:"type"`
	Member                           employeeIdentityCredentialMember `json:"member"`
}

type employeeIdentityCredentialMember struct {
	Identifier string                                 `json:"identifier"`
	Member     employeeIdentityCredentialMemberMember `json:"member"`
	RoleName   string                                 `json:"roleName"`
	Type       string                                 `json:"type"`
}

type employeeIdentityCredentialMemberMember struct {
	FamilyName string `json:"familyName"`
	Initials   string `json:"initials"`
	Type       string `json:"type"`
}

type verificationError struct {
	err error
}

func (v verificationError) Error() string {
	return v.err.Error()
}

func (v verificationError) Is(other error) bool {
	_, is := other.(verificationError)
	return is
}

func newVerificationError(error string) error {
	return verificationError{err: errors.New(error)}
}
