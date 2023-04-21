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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"time"
)

func (v service) VerifyVP(vp vc.VerifiablePresentation, validAt *time.Time) (contract.VPVerificationResult, error) {
	result := selfsignedVerificationResult{
		Status: contract.Invalid,
	}

	// 1. verify the proof and check for security requirements
	credentialSubject, proof, err := v.verifyVP(vp, validAt)
	if err != nil {
		if errors.As(err, &verificationError{}) {
			result.InvalidReason = err.Error()
			return result, nil
		}
		return nil, err
	}

	// 2. Contract validation
	c, err := contract.ParseContractString(proof.Challenge, v.validContracts)
	if err != nil {
		result.InvalidReason = err.Error()
		return result, nil
	}
	t := time.Now()
	if validAt != nil {
		t = *validAt
	}
	err = c.VerifyForGivenTime(t)
	if err != nil {
		result.InvalidReason = err.Error()
		return result, nil
	}

	// 3. check for mandatory attributes in credentialSubject
	if err = validateRequiredAttributes(credentialSubject); err != nil {
		result.InvalidReason = err.Error()
		return result, nil
	}

	// TODO add role? See #2047
	disclosedAttributes := map[string]string{
		services.InitialsTokenClaim:   credentialSubject.Member.Member.Initials,
		services.FamilyNameTokenClaim: credentialSubject.Member.Member.FamilyName,
		services.UsernameClaim:        credentialSubject.Member.Identifier,
		services.EidasIALClaim:        "low",
	}

	return selfsignedVerificationResult{
		Status: contract.Valid,
		// extract organization attributes and add them to the result
		contractAttributes:  c.Params,
		disclosedAttributes: disclosedAttributes,
	}, nil
}

func (v service) verifyVP(vp vc.VerifiablePresentation, validAt *time.Time) (credentialSubject employeeIdentityCredentialSubject, proof vc.JSONWebSignature2020Proof, resultErr error) {
	vcs, err := v.vcr.Verifier().VerifyVP(vp, true, validAt)
	if err != nil {
		if errors.As(err, &verifier.VerificationError{}) {
			resultErr = newVerificationError(err.Error())
			return
		}
		resultErr = err
		return
	}

	if len(vcs) != 1 {
		resultErr = newVerificationError("exactly 1 EmployeeIdentityCredential is required")
		return
	}
	if len(vp.Proof) != 1 {
		resultErr = newVerificationError("exactly 1 Proof is required")
		return
	}
	bytes, _ := json.Marshal(vp.Proof[0])
	_ = json.Unmarshal(bytes, &proof)
	if proof.Proof.Type != ssi.JsonWebSignature2020 {
		resultErr = newVerificationError("proof must be of type JsonWebSignature2020")
		return
	}
	vc := vcs[0]
	signingMethod := proof.VerificationMethod
	signingMethod.Fragment = ""
	if vc.Issuer.String() != signingMethod.String() {
		resultErr = newVerificationError("signer must be credential issuer")
		return
	}
	bytes, _ = json.Marshal(vc.CredentialSubject[0])
	_ = json.Unmarshal(bytes, &credentialSubject)
	if vc.Issuer.String() != credentialSubject.ID {
		resultErr = newVerificationError("signer must be credentialSubject")
		return
	}

	return credentialSubject, proof, nil
}

func validateRequiredAttributes(credentialSubject employeeIdentityCredentialSubject) error {
	// check for mandatory attrs
	if credentialSubject.Type != "Organization" {
		return errors.New("credentialSubject.type must be \"Organization\"")
	}
	if len(credentialSubject.Member.Identifier) == 0 {
		return errors.New("credentialSubject.member.identifier is required")
	}
	if len(credentialSubject.Member.Member.Initials) == 0 {
		return errors.New("credentialSubject.member.member.initials is required")
	}
	if len(credentialSubject.Member.Member.FamilyName) == 0 {
		return errors.New("credentialSubject.member.member.familyName is required")
	}
	if credentialSubject.Member.Type != "EmployeeRole" {
		return errors.New("credentialSubject.member.type must be \"EmployeeRole\"")
	}
	if credentialSubject.Member.Member.Type != "Person" {
		return errors.New("credentialSubject.member.member.type must be \"Person\"")
	}
	return nil
}

type selfsignedVerificationResult struct {
	Status              contract.State
	InvalidReason       string
	contractAttributes  map[string]string
	disclosedAttributes map[string]string
}

func (s selfsignedVerificationResult) Validity() contract.State {
	return s.Status
}

func (s selfsignedVerificationResult) Reason() string {
	return s.InvalidReason
}

func (s selfsignedVerificationResult) VPType() string {
	return VerifiablePresentationType
}

func (s selfsignedVerificationResult) DisclosedAttribute(key string) string {
	return s.disclosedAttributes[key]
}

func (s selfsignedVerificationResult) ContractAttribute(key string) string {
	return s.ContractAttribute(key)
}

func (s selfsignedVerificationResult) DisclosedAttributes() map[string]string {
	return s.disclosedAttributes
}

func (s selfsignedVerificationResult) ContractAttributes() map[string]string {
	return s.contractAttributes
}
