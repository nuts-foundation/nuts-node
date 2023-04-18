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
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/controllers"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"net/http"
	"time"
)

const credentialType = "NutsEmployeeCredential"

// SessionStore is a contract signer and verifier that always succeeds
// The SessionStore signer is not supposed to be used in a clustered context unless consecutive calls arrive at the same instance
type signer struct {
	store types.SessionStore
	vcr   vcr.VCR
}

func NewEmployeeIDSigner(vcr vcr.VCR) contract.Signer {
	return &signer{
		// NewSessionStore returns an initialized SessionStore
		store: NewSessionStore(),
		vcr:   vcr,
	}
}

func (v signer) SigningSessionStatus(ctx context.Context, sessionID string) (contract.SigningSessionResult, error) {
	s, ok := v.store.Load(sessionID)
	if !ok {
		return nil, services.ErrSessionNotFound
	}
	var vp *vc.VerifiablePresentation
	issuerID, err := did.ParseDID(s.Employer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer DID: %w", err)
	}

	if s.Status == SessionCompleted {
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

func (v signer) StartSigningSession(rawContractText string, params map[string]interface{}) (contract.SessionPointer, error) {
	sessionBytes := make([]byte, 16)
	_, _ = rand.Reader.Read(sessionBytes)

	secret := make([]byte, 16)
	_, _ = rand.Reader.Read(sessionBytes)

	sessionID := hex.EncodeToString(sessionBytes)
	s := types.Session{
		Contract: rawContractText,
		Status:   SessionCreated,
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

	return sessionPointer{
		sessionID: sessionID,
		url:       "https://example.com", // placeholder, convert to template
	}, nil
}

//func (v signer) MountHandlerFunc(router core.EchoRouter) error {
//	h := controllers.Handler{}
//	router.Add("GET", "/auth/v1/means/employee_id/:sessionID", echo.WrapHandler(http.HandlerFunc(v.HandleFormRequest)))
//	return nil
//}

func (v signer) Routes(router core.EchoRouter) {
	h := controllers.NewHandler(v.store)

	// Add test data
	v.store.Store("1", types.Session{
		Contract: "contract",
		Status:   SessionCreated,
		Employee: types.Employee{
			Identifier: "123",
			RoleName:   "Verpleegkundige",
			Initials:   "J.",
			FamilyName: "de Vries",
		},
	})

	h.Routes(router)
}

func (v signer) HandleFormRequest(w http.ResponseWriter, r *http.Request) {
}
