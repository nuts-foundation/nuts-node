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
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
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

type SessionStore interface {
	contract.Signer
	contract.VPVerifier
}

// SessionStore is a contract signer and verifier that always succeeds
// The SessionStore signer is not supposed to be used in a clustered context unless consecutive calls arrive at the same instance
type sessionStore struct {
	sessions map[string]session
}

// NewSessionStore returns an initialized SessionStore
func NewSessionStore() SessionStore {
	return sessionStore{sessions: map[string]session{}}
}

// session contains the contract text and session signing status
type session struct {
	contract string
	status   string
	Employer string
	Employee Employee `json:"employee"`
}

type Employee struct {
	Identifier string `json:"identifier"`
	RoleName   string `json:"roleName"`
	Initials   string `json:"initials"`
	FamilyName string `json:"familyName"`
}

type sessionPointer struct {
	sessionID string `json:"sessionID"`
	url       string `json:"url"`
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
	id      string
	status  string
	request string
}

func (s signingSessionResult) Status() string {
	return s.status
}

func (s signingSessionResult) VerifiablePresentation() (*vc.VerifiablePresentation, error) {
	// todo: this will always mean the API returns an empty VP
	return nil, nil
}
