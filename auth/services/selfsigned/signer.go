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
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"time"
)

const credentialType = "NutsEmployeeCredential"

func (v service) SigningSessionStatus(ctx context.Context, sessionID string) (contract.SigningSessionResult, error) {
	s, ok := v.sessions[sessionID]
	if !ok {
		return nil, services.ErrSessionNotFound
	}
	var vp *vc.VerifiablePresentation

	if s.status == SessionCompleted {
		expirationData := time.Now().Add(24 * time.Hour)
		credentialOptions := vc.VerifiableCredential{
			Context:           []ssi.URI{credential.NutsV1ContextURI},
			Type:              []ssi.URI{vc.VerifiableCredentialTypeV1URI(), ssi.MustParseURI(credentialType)},
			Issuer:            s.issuerDID.URI(),
			IssuanceDate:      time.Now(),
			ExpirationDate:    &expirationData,
			CredentialSubject: s.credentialSubject(),
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
				Challenge:    &s.contract,
				ProofPurpose: proof.AuthenticationProofPurpose,
			},
		}
		vp, err = v.vcr.Holder().BuildVP(ctx, []vc.VerifiableCredential{*verifiableCredential}, presentationOptions, &s.issuerDID, true)
		if err != nil {
			return nil, fmt.Errorf("build VP failed: %w", err)
		}
	}

	return signingSessionResult{
		id:                     sessionID,
		status:                 s.status,
		request:                s.contract,
		verifiablePresentation: vp,
	}, nil
}

func (v service) StartSigningSession(rawContractText string, params map[string]interface{}) (contract.SessionPointer, error) {
	sessionBytes := make([]byte, 16)
	rand.Reader.Read(sessionBytes)

	sessionID := hex.EncodeToString(sessionBytes)
	s := session{
		contract: rawContractText,
		status:   SessionCreated,
	}
	// load params directly into session
	marshalled, err := json.Marshal(params)
	// only functions or other weird constructions can cause an error here. No need for custom error handling.
	if err != nil {
		return nil, err
	}
	// impossible to get an error here since both the pointer and the data is under our control.
	_ = json.Unmarshal(marshalled, &s.params)

	// Parse the DID here so we can return an error
	did, err := did.ParseDID(s.params.Employer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse employer param as DID: %w", err)
	}
	s.issuerDID = *did
	v.sessions[sessionID] = s

	return sessionPointer{
		sessionID: sessionID,
		url:       "https://example.com", // placeholder, convert to template
	}, nil
}
