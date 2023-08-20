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
	"encoding/json"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"time"
)

func (v validator) VerifyVP(vp vc.VerifiablePresentation, validAt *time.Time) (contract.VPVerificationResult, error) {
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
	if proof.Challenge == nil {
		result.InvalidReason = "challenge is required"
		return result, nil
	}

	c, err := contract.ParseContractString(*proof.Challenge, v.validContracts)
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

	disclosedAttributes := map[string]string{
		services.InitialsTokenClaim:   credentialSubject.Member.Member.Initials,
		services.FamilyNameTokenClaim: credentialSubject.Member.Member.FamilyName,
		services.UsernameClaim:        credentialSubject.Member.Identifier,
		services.AssuranceLevelClaim:  "low",
	}
	if credentialSubject.Member.RoleName != nil {
		disclosedAttributes[services.UserRoleClaim] = *credentialSubject.Member.RoleName
	}

	return selfsignedVerificationResult{
		Status: contract.Valid,
		// extract organization attributes and add them to the result
		contractAttributes:  c.Params,
		disclosedAttributes: disclosedAttributes,
	}, nil
}

func (v validator) verifyVP(vp vc.VerifiablePresentation, validAt *time.Time) (credentialSubject types.EmployeeIdentityCredentialSubject, proof vc.JSONWebSignature2020Proof, resultErr error) {
	// #2428: NutsEmployeeCredential should be valid (signature), but does not need to be trusted.
	vcs, err := v.vcr.Verifier().VerifyVP(vp, true, true, validAt)
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
	var credentialSubjects []types.EmployeeIdentityCredentialSubject
	_ = vc.UnmarshalCredentialSubject(&credentialSubjects)
	if len(credentialSubjects) != 1 {
		resultErr = newVerificationError("exactly 1 credentialSubject is required")
		return
	}
	credentialSubject = credentialSubjects[0]
	if vc.Issuer.String() != credentialSubject.ID {
		resultErr = newVerificationError("signer must be credentialSubject")
		return
	}

	// #2428: NutsEmployeeCredential trust is derived from the fact that the issuer has a trusted NutsOrganizationCredential
	searchTerms := []vcr.SearchTerm{
		{IRIPath: jsonld.CredentialSubjectPath, Value: credentialSubject.ID},
		{IRIPath: jsonld.OrganizationNamePath, Type: vcr.NotNil},
		{IRIPath: jsonld.OrganizationCityPath, Type: vcr.NotNil},
	}
	nutsOrgCreds, err := v.vcr.Search(context.TODO(), searchTerms, false, validAt)
	if err != nil {
		resultErr = fmt.Errorf("unable to check NutsEmployeeCredential trust status using NutsOrganizationCredential: %w", err)
		return
	}
	if len(nutsOrgCreds) == 0 {
		resultErr = newVerificationError("NutsEmployeeCredential rejected, issuer does not have a trusted NutsOrganizationCredential")
		return
	}

	return credentialSubject, proof, nil
}

func validateRequiredAttributes(credentialSubject types.EmployeeIdentityCredentialSubject) error {
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

type validator struct {
	vcr            vcr.VCR
	validContracts contract.TemplateStore
}

func NewValidator(vcrInstance vcr.VCR, contractStore contract.TemplateStore) contract.VPVerifier {
	return validator{
		vcr:            vcrInstance,
		validContracts: contractStore,
	}
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
	return s.contractAttributes[key]
}

func (s selfsignedVerificationResult) DisclosedAttributes() map[string]string {
	return s.disclosedAttributes
}

func (s selfsignedVerificationResult) ContractAttributes() map[string]string {
	return s.contractAttributes
}
