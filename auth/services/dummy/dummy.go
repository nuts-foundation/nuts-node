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
 */

package dummy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
)

// ContractFormat is the contract format type
const ContractFormat = contract.SigningMeans("dummy")

// VerifiablePresentationType is the dummy verifiable presentation type
const VerifiablePresentationType = contract.VPType("DummyVerifiablePresentation")

// NoSignatureType is a VerifiablePresentation Proof type where no signature is given
const NoSignatureType = "NoSignature"

// SessionCreated represents the session state after creation
const SessionCreated = "created"

// SessionInProgress represents the session state after the first SessionStatus call
const SessionInProgress = "in-progress"

// SessionCompleted represents the session state after the second SessionStatus call
const SessionCompleted = "completed"

var errNotEnabled = errors.New("not allowed in strict mode")

// Dummy is a contract signer and verifier that always succeeds unless you try to use it in strict mode
// The dummy signer is not supposed to be used in a clustered context unless consecutive calls arrive at the same instance
type Dummy struct {
	InStrictMode bool
	Sessions     map[string]string
	Status       map[string]string
}

// Presentation is a VerifiablePresentation without valid cryptographic proofs
// It is only usable in non-strict mode.
type Presentation struct {
	contract.VerifiablePresentationBase
	Proof Proof
}

// Proof holds the Proof generated from the dummy Resolve
type Proof struct {
	// Proof type, mandatory
	Type string
	// Contract as how it was presented to the user
	Contract string
	// Initials form the signing means
	Initials string
	// Lastname form the signing means
	Lastname string
	// Birthdate form the signing means
	Birthdate string
	// Email form the signing means
	Email string
}

// SignedToken is the Dummy implementation of a Signed token.
// It can be used in the dummy.Service service.
type SignedToken struct {
	signerAttributes map[string]string
	contract         contract.Contract
}

// SignerAttributes returns the attributes used to sign the token
func (d SignedToken) SignerAttributes() (map[string]string, error) {
	return d.signerAttributes, nil
}

// Contract returns the contract
func (d SignedToken) Contract() contract.Contract {
	return d.contract
}

// sessionPointer contains a information to facilitate session discoverability for the signing means
type sessionPointer struct {
	sessionID string
}

// SessionID returns a string which can be used by the signing means to find the session
func (s sessionPointer) SessionID() string {
	return s.sessionID
}

// Payload returns always the dummy value
func (s sessionPointer) Payload() []byte {
	return []byte("dummy")
}

func (s sessionPointer) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SessionID string `json:"sessionID"`
	}{SessionID: s.sessionID})
}

type signingSessionResult struct {
	ID      string
	State   string
	Request string
}

// Status returns the current state of the signing session
func (d signingSessionResult) Status() string {
	return d.State
}

// VerifiablePresentation returns the contract.VerifiablePresentation if the session is completed, nil otherwise.
func (d signingSessionResult) VerifiablePresentation() (contract.VerifiablePresentation, error) {
	// todo: the contract template should be used to select the dummy attributes to add

	if d.Status() != SessionCompleted {
		return nil, nil
	}

	return Presentation{
		VerifiablePresentationBase: contract.VerifiablePresentationBase{
			Context: []string{contract.VerifiableCredentialContext},
			Type:    []contract.VPType{contract.VerifiablePresentationType, VerifiablePresentationType},
		},
		Proof: Proof{
			Type:      NoSignatureType,
			Initials:  "I",
			Lastname:  "Tester",
			Birthdate: "1980-01-01",
			Email:     "tester@example.com",
			Contract:  d.Request,
		},
	}, nil
}

// VerifyVP check a Dummy VerifiablePresentation. It Returns a verificationResult if all was fine, an error otherwise.
func (d Dummy) VerifyVP(rawVerifiablePresentation []byte, checkTime *time.Time) (*contract.VPVerificationResult, error) {
	if d.InStrictMode {
		return nil, errNotEnabled
	}

	p := Presentation{}
	if err := json.Unmarshal(rawVerifiablePresentation, &p); err != nil {
		return nil, err
	}

	c, err := contract.ParseContractString(p.Proof.Contract, contract.StandardContractTemplates)
	if err != nil {
		return nil, err
	}

	return &contract.VPVerificationResult{
		Validity: contract.Valid,
		VPType:   VerifiablePresentationType,
		DisclosedAttributes: map[string]string{
			"initials":  p.Proof.Initials,
			"lastname":  p.Proof.Lastname,
			"birthdate": p.Proof.Birthdate,
			"email":     p.Proof.Initials,
		},
		ContractAttributes: c.Params,
	}, nil
}

// SigningSessionStatus looks up the session by the provided sessionID param.
// When the session exists it returns the current state and advances the state to the next one.
// When the session is SessionComplete, it removes the session from the sessionStore.
func (d Dummy) SigningSessionStatus(sessionID string) (contract.SigningSessionResult, error) {
	if d.InStrictMode {
		return nil, errNotEnabled
	}

	state, ok := d.Status[sessionID]
	if !ok {
		return nil, services.ErrSessionNotFound
	}

	session, ok := d.Sessions[sessionID]
	if !ok {
		return nil, services.ErrSessionNotFound
	}

	// increase session status everytime this request is made
	switch state {
	case SessionCreated:
		d.Status[sessionID] = SessionInProgress
	case SessionInProgress:
		d.Status[sessionID] = SessionCompleted
	case SessionCompleted:
		delete(d.Status, sessionID)
		delete(d.Sessions, sessionID)
	}
	return signingSessionResult{
		ID:      sessionID,
		State:   state,
		Request: session,
	}, nil
}

// StartSigningSession starts a Dummy session. It takes any string and stores it under a random sessionID.
// This method is not available in strictMode
// returns the sessionPointer with the sessionID
func (d Dummy) StartSigningSession(rawContractText string) (contract.SessionPointer, error) {
	if d.InStrictMode {
		return nil, errNotEnabled
	}
	sessionBytes := make([]byte, 16)
	rand.Reader.Read(sessionBytes)

	sessionID := hex.EncodeToString(sessionBytes)
	d.Status[sessionID] = SessionCreated
	d.Sessions[sessionID] = rawContractText

	return sessionPointer{
		sessionID: sessionID,
	}, nil
}
