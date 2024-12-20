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
 *
 */

package credential

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/vcr/revocation"
	"github.com/nuts-foundation/nuts-node/vdr/didx509"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/url"
	"strings"
)

// Validator is the interface specific VC verification.
// Every VC will have its own rules of verification.
type Validator interface {
	// Validate the given credential according to the rules of the VC type.
	Validate(credential vc.VerifiableCredential) error
}

// errValidation is a common error indicating validation failed
var errValidation = errors.New("validation failed")

type defaultCredentialValidator struct {
}

func (d defaultCredentialValidator) Validate(credential vc.VerifiableCredential) error {
	if !credential.IsType(vc.VerifiableCredentialTypeV1URI()) {
		return fmt.Errorf("%w: type 'VerifiableCredential' is required", errValidation)
	}

	if !credential.ContainsContext(vc.VCContextV1URI()) {
		return fmt.Errorf("%w: default context is required", errValidation)
	}

	if credential.Issuer.String() == "" {
		return fmt.Errorf("%w: 'issuer' is required", errValidation)
	}

	if credential.ID == nil {
		return fmt.Errorf("%w: 'ID' is required", errValidation)
	}

	if credential.IssuanceDate.IsZero() {
		return fmt.Errorf("%w: 'issuanceDate' is required", errValidation)
	}

	// CredentialStatus is not specific to the credential type and the syntax (not status) should be checked here.
	if err := validateCredentialStatus(credential); err != nil {
		return fmt.Errorf("%w: invalid credentialStatus: %w", errValidation, err)
	}

	return nil
}

// validateCredentialStatus validates the
func validateCredentialStatus(credential vc.VerifiableCredential) error {
	// exit if the credential does not contain a status
	if credential.CredentialStatus == nil {
		return nil
	}

	// get base form of all credentialStatus
	statuses, err := credential.CredentialStatuses()
	if err != nil {
		return err
	}

	// validate per CredentialStatus.Type
	for _, credentialStatus := range statuses {
		// base requirements
		if credentialStatus.ID.String() == "" {
			return errors.New("credentialStatus.id is required")
		}
		if credentialStatus.Type == "" {
			return errors.New("credentialStatus.type is required")
		}

		// only validate StatusList2021Entry for now
		switch credentialStatus.Type {
		case revocation.StatusList2021EntryType:
			// TODO: json.AllFieldsDefined validator should be sufficient?
			if !credential.ContainsContext(revocation.StatusList2021ContextURI) {
				return errors.New("StatusList2021 context is required")
			}

			var cs revocation.StatusList2021Entry
			if err = json.Unmarshal(credentialStatus.Raw(), &cs); err != nil {
				return err
			}
			if err = cs.Validate(); err != nil {
				return err
			}
		}
	}

	// valid
	return nil
}

// nutsOrganizationCredentialValidator checks if there's a 'name' and 'city' in the 'organization' struct
type nutsOrganizationCredentialValidator struct {
}

func (d nutsOrganizationCredentialValidator) Validate(credential vc.VerifiableCredential) error {
	var target = make([]NutsOrganizationCredentialSubject, 0)

	err := validateNutsCredentialID(credential)
	if err != nil {
		return err
	}

	if !credential.IsType(*NutsOrganizationCredentialTypeURI) {
		return fmt.Errorf("%w: type '%s' is required", errValidation, NutsOrganizationCredentialType)
	}

	if !credential.ContainsContext(NutsV1ContextURI) {
		return fmt.Errorf("%w: context '%s' is required", errValidation, NutsV1ContextURI.String())
	}

	// if it fails, length check will trigger
	_ = credential.UnmarshalCredentialSubject(&target)
	if len(target) != 1 {
		return fmt.Errorf("%w: single CredentialSubject expected", errValidation)
	}
	cs := target[0]

	if cs.Organization == nil {
		return fmt.Errorf("%w: 'credentialSubject.organization' is empty", errValidation)
	}
	if cs.ID == "" {
		return fmt.Errorf("%w: 'credentialSubject.ID' is nil", errValidation)
	}
	if _, err = did.ParseDID(cs.ID); err != nil {
		return fmt.Errorf("%w: invalid 'credentialSubject.id': %w", errValidation, err)
	}

	if n, ok := cs.Organization["name"]; !ok || len(strings.TrimSpace(n)) == 0 {
		return fmt.Errorf("%w: 'credentialSubject.name' is empty", errValidation)
	}

	if c, ok := cs.Organization["city"]; !ok || len(strings.TrimSpace(c)) == 0 {
		return fmt.Errorf("%w: 'credentialSubject.city' is empty", errValidation)
	}

	return (defaultCredentialValidator{}).Validate(credential)
}

// nutsAuthorizationCredentialValidator checks for mandatory fields: id, purposeOfUse.
// Also checks whether the specified resources
type nutsAuthorizationCredentialValidator struct {
}

func (d nutsAuthorizationCredentialValidator) Validate(credential vc.VerifiableCredential) error {
	var target = make([]NutsAuthorizationCredentialSubject, 0)

	err := validateNutsCredentialID(credential)
	if err != nil {
		return err
	}

	if !credential.IsType(*NutsAuthorizationCredentialTypeURI) {
		return fmt.Errorf("%w: type '%s' is required", errValidation, NutsAuthorizationCredentialType)
	}

	if !credential.ContainsContext(NutsV1ContextURI) {
		return fmt.Errorf("%w: context '%s' is required", errValidation, NutsV1ContextURI.String())
	}

	// if it fails, length check will trigger
	_ = credential.UnmarshalCredentialSubject(&target)
	if len(target) != 1 {
		return fmt.Errorf("%w: single CredentialSubject expected", errValidation)
	}
	cs := target[0]

	if len(strings.TrimSpace(cs.ID)) == 0 {
		return fmt.Errorf("%w: 'credentialSubject.ID' is nil", errValidation)
	}
	if _, err = did.ParseDID(cs.ID); err != nil {
		return fmt.Errorf("%w: invalid 'credentialSubject.id': %w", errValidation, err)
	}
	if len(strings.TrimSpace(cs.PurposeOfUse)) == 0 {
		return fmt.Errorf("%w: 'credentialSubject.PurposeOfUse' is nil", errValidation)
	}

	err = validateResources(cs.Resources)
	if err != nil {
		return err
	}

	return (defaultCredentialValidator{}).Validate(credential)
}

func validOperationTypes() []string {
	return []string{"read", "vread", "update", "patch", "delete", "history", "create", "search", "document"}
}

func validateResources(resources []Resource) error {
	for _, r := range resources {
		if len(strings.TrimSpace(r.Path)) == 0 {
			return fmt.Errorf("%w: 'credentialSubject.Resources[].Path' is required'", errValidation)
		}
		if len(r.Operations) == 0 {
			return fmt.Errorf("%w: 'credentialSubject.Resources[].Operations[]' requires at least one value", errValidation)
		}
		for _, o := range r.Operations {
			if !validOperation(o) {
				return fmt.Errorf("%w: 'credentialSubject.Resources[].Operations[]' contains an invalid operation '%s'", errValidation, o)
			}
		}
	}

	return nil
}

func validOperation(operation string) bool {
	for _, o := range validOperationTypes() {
		if o == strings.ToLower(operation) {
			return true
		}
	}
	return false
}

func validateNutsCredentialID(credential vc.VerifiableCredential) error {
	id, err := resolver.GetDIDFromURL(credential.ID.String())
	if err != nil {
		return err
	}
	if id.String() != credential.Issuer.String() {
		return fmt.Errorf("%w: credential ID must start with issuer", errValidation)
	}
	return nil
}

// x509CredentialValidator checks the did:x509 issuer and if the credentialSubject claims match the x509 certificate
type x509CredentialValidator struct {
	pkiValidator pki.Validator
}

func (d x509CredentialValidator) Validate(credential vc.VerifiableCredential) error {
	didX509Issuer, err := did.ParseDID(credential.Issuer.String())
	if err != nil {
		return errors.Join(errValidation, err)
	}
	x509resolver := didx509.NewResolver()
	resolveMetadata := resolver.ResolveMetadata{}
	if credential.Format() == vc.JWTCredentialProofFormat {
		headers, err := crypto.ExtractProtectedHeaders(credential.Raw())
		if err != nil {
			return fmt.Errorf("%w: invalid JWT headers: %w", errValidation, err)
		}
		resolveMetadata.JwtProtectedHeaders = headers
	} else {
		// unsupported format
		return fmt.Errorf("%w: unsupported credential format: %s", errValidation, credential.Format())
	}
	_, _, err = x509resolver.Resolve(*didX509Issuer, &resolveMetadata)
	if err != nil {
		return fmt.Errorf("%w: invalid issuer: %w", errValidation, err)
	}

	if err = validatePolicyAssertions(credential); err != nil {
		return fmt.Errorf("%w: %w", errValidation, err)
	}

	chainHeader, _ := resolveMetadata.GetProtectedHeaderChain(jwk.X509CertChainKey) // already succeeded for resolve
	// convert cert.Chain to []*x509.Certificate
	chain := make([]*x509.Certificate, chainHeader.Len())
	for i := 0; i < chainHeader.Len(); i++ {
		base64Cert, _ := chainHeader.Get(i)
		der, err := base64.StdEncoding.DecodeString(string(base64Cert))
		if err != nil {
			return fmt.Errorf("%w: invalid certificate chain: %w", errValidation, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("%w: invalid certificate chain: %w", errValidation, err)
		}
		chain[i] = cert
	}
	if err = d.pkiValidator.CheckCRL(chain); err != nil {
		return fmt.Errorf("%w: %w", errValidation, err)
	}

	return (defaultCredentialValidator{}).Validate(credential)
}

// validatePolicyAssertions checks if the credentialSubject claims match the did issuer policies
func validatePolicyAssertions(credential vc.VerifiableCredential) error {
	// get base form of all credentialSubject
	var target = make([]map[string]interface{}, 1)
	if err := credential.UnmarshalCredentialSubject(&target); err != nil {
		return err
	}

	// we create a map of policyName to policyValue, then we split the policyValue into another map
	policyMap := make(map[string]map[string]string)
	policies := strings.Split(credential.Issuer.String(), "::")
	if len(policies) < 2 {
		return fmt.Errorf("invalid did:x509 policy")
	}
	for _, policy := range policies[1:] {
		policySplit := strings.Split(policy, ":")
		if len(policySplit)%2 != 1 { // policy name and 2*n key/value pairs
			return fmt.Errorf("invalid did:x509 policy '%s'", policy)
		}
		policyName := policySplit[0]
		policyMap[policyName] = make(map[string]string)
		for i := 1; i < len(policySplit); i += 2 {
			unscaped, _ := url.PathUnescape(policySplit[i+1])
			policyMap[policyName][policySplit[i]] = unscaped
		}
	}

	// we usually don't use multiple credentialSubjects, but for this validation it doesn't matter
	for _, credentialSubject := range target {
		// remove id from target
		delete(credentialSubject, "id")

		// for each assertion create a string as "%s:%s" with key/value
		// check if the resulting string is present in the policyString
		for key, value := range credentialSubject {
			split := strings.Split(key, ":")
			if len(split) != 2 {
				return fmt.Errorf("invalid credentialSubject assertion name '%s'", key)
			}
			policyValueMap, ok := policyMap[split[0]]
			if !ok {
				return fmt.Errorf("policy '%s' not found in did:x509 policy", split[0])
			}
			policyValue, ok := policyValueMap[split[1]]
			if !ok {
				return fmt.Errorf("assertion '%s' not found in did:x509 policy", key)
			}
			if value != policyValue {
				return fmt.Errorf("invalid assertion value '%s' for '%s' did:x509 policy", value, key)
			}
		}
	}

	return nil
}
