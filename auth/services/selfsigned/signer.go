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
	"net/http"
	"net/url"
	"time"
)

const credentialType = "NutsEmployeeCredential"

// SessionStore is a contract signer and verifier that always succeeds
// The SessionStore signer is not supposed to be used in a clustered context unless consecutive calls arrive at the same instance
type signer struct {
	store     types.SessionStore
	vcr       vcr.VCR
	publicURL string
}

// NewSigner returns an initialized employee identity contract signer
func NewSigner(vcr vcr.VCR, publicURL string) contract.Signer {
	return &signer{
		// NewSessionStore returns an initialized SessionStore
		store:     NewSessionStore(),
		vcr:       vcr,
		publicURL: publicURL,
	}
}

func (v *signer) SigningSessionStatus(ctx context.Context, sessionID string) (contract.SigningSessionResult, error) {
	s, ok := v.store.Load(sessionID)
	if !ok {
		return nil, services.ErrSessionNotFound
	}
	var vp *vc.VerifiablePresentation
	issuerID, err := did.ParseDID(s.Employer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer DID: %w", err)
	}

	if s.Status == types.SessionCompleted {
		expirationData := time.Now().Add(24 * time.Hour)
		credentialOptions := vc.VerifiableCredential{
			Context:           []ssi.URI{credential.NutsV1ContextURI},
			Type:              []ssi.URI{vc.VerifiableCredentialTypeV1URI(), ssi.MustParseURI(credentialType)},
			Issuer:            issuerID.URI(),
			IssuanceDate:      time.Now(),
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
				Created:      time.Now(),
				Challenge:    &s.Contract,
				ProofPurpose: proof.AuthenticationProofPurpose,
			},
		}
		vp, err = v.vcr.Holder().BuildVP(ctx, []vc.VerifiableCredential{*verifiableCredential}, presentationOptions, issuerID, true)
		if err != nil {
			return nil, fmt.Errorf("build VP failed: %w", err)
		}
	}

	return signingSessionResult{
		id:                     sessionID,
		status:                 s.Status,
		request:                s.Contract,
		verifiablePresentation: vp,
	}, nil
}

func (v *signer) StartSigningSession(userContract contract.Contract, params map[string]interface{}) (contract.SessionPointer, error) {
	if err := checkSessionParams(params); err != nil {
		return nil, services.NewInvalidContractRequestError(fmt.Errorf("invalid session params: %w", err))
	}

	// TODO: check if the contract name and city matches the employeeDID

	sessionBytes := make([]byte, 16)
	_, _ = rand.Reader.Read(sessionBytes)

	secret := make([]byte, 16)
	_, _ = rand.Reader.Read(sessionBytes)

	sessionID := hex.EncodeToString(sessionBytes)
	s := types.Session{
		Contract: userContract.RawContractText,
		Status:   types.SessionCreated,
		Secret:   hex.EncodeToString(secret),
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

	urlStr := fmt.Sprintf("%s/%s/%s", v.publicURL, "public/auth/v1/means/employeeid", sessionID)
	pageURL, err := url.ParseRequestURI(urlStr)
	if err != nil {
		return nil, err
	}
	return sessionPointer{
		sessionID: sessionID,
		url:       pageURL.String(),
	}, nil
}

// Check for the following structure:
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
	_, ok = employeeMap["roleName"]
	if !ok {
		return fmt.Errorf("missing employee roleName")
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

	// Add test data
	v.store.Store("1", types.Session{
		Contract: "NL:BehandelaarLogin:v3 Hierbij verklaar ik te handelen in naam van MijEenZorg te Hengelo. Deze verklaring is geldig van dinsdag, 18 april 2023 17:32:00 tot dinsdag, 18 april 2023 19:32:00.",
		Status:   types.SessionCreated,
		Employee: types.Employee{
			Identifier: "123",
			RoleName:   "Verpleegkundige",
			Initials:   "J.",
			FamilyName: "de Vries",
		},
	})
	// Add test data
	v.store.Store("2", types.Session{
		Contract: "EN:PractitionerLogin:v3 I hereby declare to act on behalf of MijnEenZorg located in Hengelo. This declaration is valid from tuesday 18 april 2023 17:32:00 until tuesday 19 april 2023 17:32:00.",
		Status:   types.SessionCreated,
		Employee: types.Employee{
			Identifier: "123",
			RoleName:   "Verpleegkundige",
			Initials:   "J.",
			FamilyName: "de Vries",
		},
	})

	h.Routes(router)
}

func (v *signer) HandleFormRequest(w http.ResponseWriter, r *http.Request) {
}
