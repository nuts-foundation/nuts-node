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
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/json"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
)

// ContractFormat is the contract format type
const ContractFormat = "dummy"

// VerifiablePresentationType is the dummy verifiable presentation type
const VerifiablePresentationType = "DummyVerifiablePresentation"

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

// Proof holds the Proof generated from the dummy Signer
type Proof struct {
	// Proof type, mandatory
	Type string
	// Contract as how it was presented to the user
	Contract string
	// FamilyName from the signing means
	FamilyName string
	// GivenName from the signing means
	Initials string
	// Prefix from the signing means
	Prefix string
	// Email from the signing means
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

type dummyVPVerificationResult struct {
	disclosedAttributes map[string]string
	contractAttributes  map[string]string
}

func (d dummyVPVerificationResult) Validity() contract.State {
	return contract.Valid
}

func (d dummyVPVerificationResult) Reason() string {
	return ""
}

func (d dummyVPVerificationResult) VPType() string {
	return VerifiablePresentationType
}

func (d dummyVPVerificationResult) DisclosedAttribute(key string) string {
	return d.disclosedAttributes[key]
}

func (d dummyVPVerificationResult) ContractAttribute(key string) string {
	return d.contractAttributes[key]
}

func (d dummyVPVerificationResult) DisclosedAttributes() map[string]string {
	return d.disclosedAttributes
}

func (d dummyVPVerificationResult) ContractAttributes() map[string]string {
	return d.contractAttributes
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
func (d signingSessionResult) VerifiablePresentation() (*vc.VerifiablePresentation, error) {
	// todo: the contract template should be used to select the dummy attributes to add

	if d.Status() != SessionCompleted {
		return nil, nil
	}

	return &vc.VerifiablePresentation{
		Context: []ssi.URI{vc.VCContextV1URI()},
		Type:    []ssi.URI{vc.VerifiablePresentationTypeV1URI(), ssi.MustParseURI(VerifiablePresentationType)},
		Proof: []interface{}{
			Proof{
				Type:       NoSignatureType,
				Initials:   "I",
				Prefix:     "von",
				FamilyName: "Dummy",
				Email:      "tester@example.com",
				Contract:   d.Request},
		},
	}, nil
}

func (d Dummy) Start(_ context.Context) {
}

// VerifyVP check a Dummy VerifiablePresentation. It Returns a verificationResult if all was fine, an error otherwise.
func (d Dummy) VerifyVP(vp vc.VerifiablePresentation, _ *time.Time) (contract.VPVerificationResult, error) {
	if d.InStrictMode {
		return nil, errNotEnabled
	}

	proofs := make([]Proof, 0)
	if err := vp.UnmarshalProofValue(&proofs); err != nil {
		return nil, err
	}

	if len(proofs) != 1 {
		return nil, fmt.Errorf("invalid number of proofs in Dummy proof: %v", proofs)
	}

	proof := proofs[0]
	c, err := contract.ParseContractString(proof.Contract, contract.StandardContractTemplates)
	if err != nil {
		return nil, err
	}

	// follows openid default claims
	return dummyVPVerificationResult{
		disclosedAttributes: map[string]string{
			services.InitialsTokenClaim:   proof.Initials,
			services.PrefixTokenClaim:     proof.Prefix,
			services.FamilyNameTokenClaim: proof.FamilyName,
			services.EmailTokenClaim:      proof.Email,
			services.UsernameClaim:        proof.Email,
			services.AssuranceLevelClaim:  "low",
		},
		contractAttributes: c.Params,
	}, nil
}

// SigningSessionStatus looks up the session by the provided sessionID param.
// When the session exists it returns the current state and advances the state to the next one.
// When the session is SessionComplete, it removes the session from the sessionStore.
func (d Dummy) SigningSessionStatus(_ context.Context, sessionID string) (contract.SigningSessionResult, error) {
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
func (d Dummy) StartSigningSession(contract contract.Contract, params map[string]interface{}) (contract.SessionPointer, error) {
	if d.InStrictMode {
		return nil, errNotEnabled
	}
	sessionBytes := make([]byte, 16)
	_, _ = rand.Reader.Read(sessionBytes)

	sessionID := hex.EncodeToString(sessionBytes)
	d.Status[sessionID] = SessionCreated
	d.Sessions[sessionID] = contract.RawContractText

	return sessionPointer{
		sessionID: sessionID,
	}, nil
}
