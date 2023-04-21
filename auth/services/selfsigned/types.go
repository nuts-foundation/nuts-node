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
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/vcr"
)

// ContractFormat is the contract format type
const ContractFormat = "selfsigned"

// VerifiablePresentationType is the dummy verifiable presentation type
const VerifiablePresentationType = "NutsSelfSignedPresentation"

// SessionCreated represents the session state after creation
const SessionCreated = "created"

// SessionInProgress represents the session state after rendering the html
const SessionInProgress = "in-progress"

// SessionCompleted represents the session state after the user has accepted the contract
const SessionCompleted = "completed"

type Service interface {
	contract.Signer
	contract.VPVerifier
}

// Service is a contract signer and verifier that always succeeds
// The Service signer is not supposed to be used in a clustered context unless consecutive calls arrive at the same instance
type service struct {
	sessions map[string]session
	vcr      vcr.VCR
}

// NewService returns an initialized Service
func NewService(vcr vcr.VCR) Service {
	return &service{
		sessions: map[string]session{},
		vcr:      vcr,
	}
}

// session contains the contract text and session signing status
type session struct {
	// contract contains the original contract text
	contract string
	// session contains the status of the session (created/completed)
	status string
	// params contains the params given to start the session
	params sessionParam
	// issuerDID contains the issuer DID, this is parsed from params['employer']
	issuerDID did.DID
}

type sessionParam struct {
	Employer string   `json:"employer"`
	Employee Employee `json:"employee"`
}

type Employee struct {
	Identifier string `json:"identifier"`
	RoleName   string `json:"roleName"`
	Initials   string `json:"initials"`
	FamilyName string `json:"familyName"`
}

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
		Page      string `json:"page"`
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

func (s session) credentialSubject() []interface{} {
	person := map[string]string{
		"type":       "Person",
		"initials":   s.params.Employee.Initials,
		"familyName": s.params.Employee.FamilyName,
	}
	role := map[string]interface{}{
		"member":     person,
		"roleName":   s.params.Employee.RoleName,
		"type":       "EmployeeRole",
		"identifier": s.params.Employee.Identifier,
	}
	credentialSubject := map[string]interface{}{
		"@type":  "Organization",
		"id":     s.params.Employer,
		"member": role,
	}
	return []interface{}{
		credentialSubject,
	}
}
