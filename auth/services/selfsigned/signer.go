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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	vc2 "github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"time"
)

const credentialType = "NutsEmployeeCredential"

func (v sessionStore) SigningSessionStatus(sessionID string) (contract.SigningSessionResult, error) {
	s, ok := v.sessions[sessionID]
	if !ok {
		return nil, services.ErrSessionNotFound
	}
	var vp *vc2.VerifiablePresentation

	if s.status == SessionCompleted {
		issuer := did.MustParseDID(s.Employer) // todo panic << validate in API?
		expirationData := time.Now().Add(24 * time.Hour)
		credentialOptions := vc2.VerifiableCredential{
			Context:           []ssi.URI{credential.NutsV1ContextURI},
			Type:              []ssi.URI{vc2.VerifiableCredentialTypeV1URI(), ssi.MustParseURI(credentialType)},
			Issuer:            issuer.URI(),
			IssuanceDate:      time.Now(),
			ExpirationDate:    &expirationData,
			CredentialSubject: s.credentialSubject(),
		}
		verifiableCredential, err := v.vcr.Issuer().Issue(context.TODO(), credentialOptions, false, false)
		if err != nil {
			return nil, err
		}
		proofOptions := proof.ProofOptions{
			Created:      time.Now(),
			Challenge:    &s.contract,
			ProofPurpose: "",
		}
		vp, err = v.vcr.Holder().BuildVP(context.TODO(), []vc2.VerifiableCredential{*verifiableCredential}, proofOptions, &issuer, true)
		if err != nil {
			return nil, err
		}
	}

	return signingSessionResult{
		id:                     sessionID,
		status:                 s.status,
		request:                s.contract,
		verifiablePresentation: vp,
	}, nil
}

func (v sessionStore) StartSigningSession(rawContractText string, params map[string]interface{}) (contract.SessionPointer, error) {
	sessionBytes := make([]byte, 16)
	rand.Reader.Read(sessionBytes)

	sessionID := hex.EncodeToString(sessionBytes)
	s := session{
		contract: rawContractText,
		status:   SessionCreated,
	}
	// load params directly into session
	marshalled, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(marshalled, &s); err != nil {
		return nil, err
	}
	v.sessions[sessionID] = s

	return sessionPointer{
		sessionID: sessionID,
		url:       "https://example.com", // placeholder, convert to template
	}, nil
}
