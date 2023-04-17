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
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"time"
)

func (v sessionStore) VerifyVP(vp vc.VerifiablePresentation, validAt *time.Time) (contract.VPVerificationResult, error) {
	// first verify the proof
	vcs, err := v.vcr.Verifier().VerifyVP(vp, true, validAt)
	if err != nil {
		if errors.As(err, &verifier.VerificationError{}) {
			return selfsignedVerificationResult{
				Status:        contract.Invalid,
				InvalidReason: err.Error(),
			}, nil
		}
		return nil, err
	}

	if len(vcs) != 1 {
		return selfsignedVerificationResult{
			Status:        contract.Invalid,
			InvalidReason: "exactly 1 EmployeeIdentityCredential is required",
		}, nil
	}
	if len(vp.Proof) != 1 {
		return selfsignedVerificationResult{
			Status:        contract.Invalid,
			InvalidReason: "exactly 1 Proof is required",
		}, nil
	}
	var proof vc.JSONWebSignature2020Proof
	bytes, _ := json.Marshal(vp.Proof[0])
	_ = json.Unmarshal(bytes, &proof)
	if proof.Proof.Type != ssi.JsonWebSignature2020 {
		return selfsignedVerificationResult{
			Status:        contract.Invalid,
			InvalidReason: "proof must be of type JsonWebSignature2020",
		}, nil
	}
	vc := vcs[0]
	signingMethod := proof.VerificationMethod
	signingMethod.Fragment = ""
	if vc.Issuer.String() != signingMethod.String() {
		return selfsignedVerificationResult{
			Status:        contract.Invalid,
			InvalidReason: "signer must be credential issuer",
		}, nil
	}
	var credentialSubject employeeIdentityCredentialSubject
	bytes, _ = json.Marshal(vc.CredentialSubject[0])
	_ = json.Unmarshal(bytes, &credentialSubject)
	if vc.Issuer.String() != credentialSubject.ID {
		return selfsignedVerificationResult{
			Status:        contract.Invalid,
			InvalidReason: "signer must be credentialSubject",
		}, nil
	}
	// TODO: get the contract and check for existence of NutsOrganizationCredential, check dates

	// check for mandatory attrs
	if credentialSubject.Type != "Organization" {
		return selfsignedVerificationResult{
			Status:        contract.Invalid,
			InvalidReason: "credentialSubject.@Type must be \"Organization\"",
		}, nil
	}
	if len(credentialSubject.Member.Identifier) == 0 {
		return selfsignedVerificationResult{
			Status:        contract.Invalid,
			InvalidReason: "credentialSubject.member.identifier is required",
		}, nil
	}
	if len(credentialSubject.Member.Member.Initials) == 0 {
		return selfsignedVerificationResult{
			Status:        contract.Invalid,
			InvalidReason: "credentialSubject.member.member.initials is required",
		}, nil
	}
	if len(credentialSubject.Member.Member.FamilyName) == 0 {
		return selfsignedVerificationResult{
			Status:        contract.Invalid,
			InvalidReason: "credentialSubject.member.member.initials is required",
		}, nil
	}
	if credentialSubject.Member.Type != "EmployeeRole" {
		return selfsignedVerificationResult{
			Status:        contract.Invalid,
			InvalidReason: "credentialSubject.member.type must be \"EmployeeRole\"",
		}, nil
	}
	if credentialSubject.Member.Member.Type != "Person" {
		return selfsignedVerificationResult{
			Status:        contract.Invalid,
			InvalidReason: "credentialSubject.member.member.type must be \"Person\"",
		}, nil
	}

	return selfsignedVerificationResult{
		Status: contract.Valid,
	}, nil
}

type selfsignedVerificationResult struct {
	Status        contract.State
	InvalidReason string
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
	return ""
}

func (s selfsignedVerificationResult) ContractAttribute(key string) string {
	return ""
}

func (s selfsignedVerificationResult) DisclosedAttributes() map[string]string {
	return map[string]string{}
}

func (s selfsignedVerificationResult) ContractAttributes() map[string]string {
	return map[string]string{}
}
