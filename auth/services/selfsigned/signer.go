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
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/web"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"net/url"
	"time"
)

const credentialType = "NutsEmployeeCredential"

// signer implements the contract.Signer interface
type signer struct {
	store     types.SessionStore
	vcr       vcr.VCR
	publicURL string
	// signingDuration is the time the user has to sign the contract
	signingDuration time.Duration
}

// NewSigner returns an initialized employee identity contract signer
func NewSigner(vcr vcr.VCR, publicURL string) contract.Signer {
	return &signer{
		// NewMemorySessionStore returns an initialized SessionStore
		store:           NewMemorySessionStore(),
		vcr:             vcr,
		publicURL:       publicURL,
		signingDuration: 10 * time.Minute,
	}
}

// SigningSessionStatus returns the status of a signing session
// If the session is completed, a VerifiablePresentation is created and added to the result
// The session is deleted after the VerifiablePresentation is created, so the completed result can only be retrieved once
func (v *signer) SigningSessionStatus(ctx context.Context, sessionID string) (contract.SigningSessionResult, error) {
	s, ok := v.store.Load(sessionID)
	if !ok {
		return nil, services.ErrSessionNotFound
	}

	var (
		vp  *vc.VerifiablePresentation
		err error
	)
	if s.Status == types.SessionCompleted {
		// Make sure no other VP will be created for this session
		if !v.store.CheckAndSetStatus(sessionID, types.SessionCompleted, types.SessionVPRequested) {
			// Another VP is already being created for this session
			// Make sure the session is deleted
			v.store.Delete(sessionID)
			return nil, services.ErrSessionNotFound
		}

		// Create the VerifiablePresentation
		vp, err = v.createVP(ctx, s, time.Now())
		if err != nil {
			return nil, fmt.Errorf("failed to create VerifiablePresentation: %w", err)
		}
	}

	// cleanup all sessions in a final state
	switch s.Status {
	case types.SessionVPRequested:
		fallthrough
	case types.SessionExpired:
		fallthrough
	case types.SessionCancelled:
		fallthrough
	case types.SessionErrored:
		v.store.Delete(sessionID)
	}

	return signingSessionResult{
		id:                     sessionID,
		status:                 s.Status,
		request:                s.Contract,
		verifiablePresentation: vp,
	}, nil
}

// createVP creates a VerifiablePresentation for the given session
func (v *signer) createVP(ctx context.Context, s types.Session, issuanceDate time.Time) (*vc.VerifiablePresentation, error) {
	issuerID, err := did.ParseDID(s.Employer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer DID: %w", err)
	}

	expirationData := issuanceDate.Add(24 * time.Hour)
	credentialOptions := vc.VerifiableCredential{
		Context:           []ssi.URI{credential.NutsV1ContextURI},
		Type:              []ssi.URI{ssi.MustParseURI(credentialType)},
		Issuer:            issuerID.URI(),
		IssuanceDate:      issuanceDate,
		ExpirationDate:    &expirationData,
		CredentialSubject: s.CredentialSubject(),
	}
	verifiableCredential, err := v.vcr.Issuer().Issue(ctx, credentialOptions, false, false)
	if err != nil {
		return nil, fmt.Errorf("issue VC failed: %w", err)
	}
	presentationOptions := holder.PresentationOptions{
		AdditionalContexts: []ssi.URI{credential.NutsV1ContextURI},
		AdditionalTypes:    []ssi.URI{ssi.MustParseURI(VerifiablePresentationType)},
		ProofOptions: proof.ProofOptions{
			Created:      issuanceDate,
			Challenge:    &s.Contract,
			ProofPurpose: proof.AuthenticationProofPurpose,
		},
	}
	return v.vcr.Wallet().BuildPresentation(ctx, []vc.VerifiableCredential{*verifiableCredential}, presentationOptions, issuerID, true)
}

func (v *signer) Start(ctx context.Context) {
	v.store.Start(ctx)
	return
}

func (v *signer) StartSigningSession(userContract contract.Contract, params map[string]interface{}) (contract.SessionPointer, error) {
	// check the session params first to provide the user with feedback if something is missing
	if err := checkSessionParams(params); err != nil {
		return nil, services.InvalidContractRequestError{Message: fmt.Errorf("invalid session params: %w", err)}
	}

	const randomByteCount = 16
	sessionBytes := make([]byte, randomByteCount)
	count, err := rand.Reader.Read(sessionBytes)
	if err != nil || count != randomByteCount {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	secret := make([]byte, randomByteCount)
	_, err = rand.Reader.Read(secret)
	if err != nil || count != randomByteCount {
		return nil, fmt.Errorf("failed to generate session secret: %w", err)
	}

	sessionID := hex.EncodeToString(sessionBytes)
	s := types.Session{
		Contract:  userContract.RawContractText,
		Status:    types.SessionCreated,
		Secret:    hex.EncodeToString(secret),
		ExpiresAt: time.Now().Add(v.signingDuration),
	}
	// load params directly into session
	marshalled, err := json.Marshal(params)
	// only functions or other weird constructions can cause an error here. No need for custom error handling.
	if err != nil {
		return nil, err
	}
	// impossible to get an error here since both the pointer and the data is under our control.
	_ = json.Unmarshal(marshalled, &s)

	// Parse the DID here so we can return an error
	employeeDID, err := did.ParseDID(params["employer"].(string))
	if err != nil {
		return nil, fmt.Errorf("failed to parse employer param as DID: %w", err)
	}
	s.Employer = employeeDID.String()
	v.store.Store(sessionID, s)

	pageURL, err := url.ParseRequestURI(core.JoinURLPaths(v.publicURL, "public/auth/v1/means/employeeid", sessionID))
	if err != nil {
		return nil, err
	}
	return sessionPointer{
		sessionID: sessionID,
		url:       pageURL.String(),
	}, nil
}

// checkSessionParams checks for the following structure:
//
//	{
//	  "employer":"did:123",
//	  "employee": {
//	    "identifier": "481",
//	    "roleName": "Verpleegkundige niveau 2",
//	    "initials": "J",
//	    "familyName": "van Dijk",
//	    "email": "j.vandijk@example.com"
//	  }
//	}
func checkSessionParams(params map[string]interface{}) error {
	_, ok := params["employer"]
	if !ok {
		return fmt.Errorf("missing employer")
	}
	employee, ok := params["employee"]
	if !ok {
		return fmt.Errorf("missing employee")
	}
	employeeMap, ok := employee.(map[string]interface{})
	if !ok {
		return fmt.Errorf("employee should be an object")
	}
	_, ok = employeeMap["identifier"]
	if !ok {
		return fmt.Errorf("missing employee identifier")
	}
	_, ok = employeeMap["initials"]
	if !ok {
		return fmt.Errorf("missing employee initials")
	}
	_, ok = employeeMap["familyName"]
	if !ok {
		return fmt.Errorf("missing employee familyName")
	}
	return nil

}

func (v *signer) Routes(router core.EchoRouter) {
	h := web.NewHandler(v.store)
	h.Routes(router)
}
