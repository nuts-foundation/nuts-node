/*
 * Copyright (C) 2026 Nuts community
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

package pe_test

import (
	"encoding/json"
	"fmt"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

func mustParsePD(jsonStr string) pe.PresentationDefinition {
	var pd pe.PresentationDefinition
	if err := json.Unmarshal([]byte(jsonStr), &pd); err != nil {
		panic(err)
	}
	return pd
}

func mustParseVC(jsonStr string) vc.VerifiableCredential {
	var cred vc.VerifiableCredential
	if err := json.Unmarshal([]byte(jsonStr), &cred); err != nil {
		panic(err)
	}
	return cred
}

// The engine picks a credential per input descriptor. A field id (patient_id) both names the
// value for token introspection and acts as a binding name.
func ExampleSelect() {
	pd := mustParsePD(`{
		"id": "example-pd",
		"input_descriptors": [{
			"id": "patient_credential",
			"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"]}]}
		}]
	}`)
	wallet := []vc.VerifiableCredential{
		mustParseVC(`{"id": "vc-1", "credentialSubject": {"patientId": "123"}}`),
	}

	result, err := pe.Select(pd, wallet)
	if err != nil {
		panic(err)
	}

	fmt.Println(result.Candidates[0].VC.ID.String())
	fmt.Println(result.Bindings["patient_id"])
	// Output:
	// vc-1
	// 123
}

// Initial bindings (the credential_selection parameter) pin a field id to a value, selecting
// the credential that carries it.
func ExampleWithInitialBindings() {
	pd := mustParsePD(`{
		"id": "example-pd",
		"input_descriptors": [{
			"id": "patient_credential",
			"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"]}]}
		}]
	}`)
	wallet := []vc.VerifiableCredential{
		mustParseVC(`{"id": "vc-1", "credentialSubject": {"patientId": "123"}}`),
		mustParseVC(`{"id": "vc-2", "credentialSubject": {"patientId": "456"}}`),
	}

	result, err := pe.Select(pd, wallet, pe.WithInitialBindings(map[string]string{"patient_id": "456"}))
	if err != nil {
		panic(err)
	}

	fmt.Println(result.Candidates[0].VC.ID.String())
	// Output: vc-2
}

// Under Strict, a wallet that can satisfy the PD in more than one materially different way is
// an error naming the descriptors to disambiguate, instead of a silent first pick.
func ExampleWithStrategy() {
	pd := mustParsePD(`{
		"id": "example-pd",
		"input_descriptors": [
			{"id": "A", "constraints": {"fields": [
				{"path": ["$.type"], "filter": {"type": "string", "const": "ACredential"}},
				{"id": "foo", "path": ["$.credentialSubject.foo"]}
			]}},
			{"id": "B", "constraints": {"fields": [
				{"path": ["$.type"], "filter": {"type": "string", "const": "BCredential"}},
				{"id": "foo", "path": ["$.credentialSubject.foo"]}
			]}}
		]
	}`)
	wallet := []vc.VerifiableCredential{
		mustParseVC(`{"id": "a1", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"foo": "X"}}`),
		mustParseVC(`{"id": "a2", "type": ["VerifiableCredential", "ACredential"], "credentialSubject": {"foo": "Y"}}`),
		mustParseVC(`{"id": "b1", "type": ["VerifiableCredential", "BCredential"], "credentialSubject": {"foo": "X"}}`),
		mustParseVC(`{"id": "b2", "type": ["VerifiableCredential", "BCredential"], "credentialSubject": {"foo": "Y"}}`),
	}

	_, err := pe.Select(pd, wallet, pe.WithStrategy(pe.Strict))

	fmt.Println(err)
	// Output: ambiguous input descriptors [A B]: multiple matching credentials
}

// The selection trace explains why each candidate was or wasn't used: here the first credential
// fails the PD's filter, and the report names the reason.
func ExampleWithSelectionTrace() {
	pd := mustParsePD(`{
		"id": "example-pd",
		"input_descriptors": [{
			"id": "patient_credential",
			"constraints": {"fields": [{"id": "patient_id", "path": ["$.credentialSubject.patientId"], "filter": {"type": "string", "const": "999"}}]}
		}]
	}`)
	wallet := []vc.VerifiableCredential{
		mustParseVC(`{"id": "vc-wrong", "credentialSubject": {"patientId": "123"}}`),
		mustParseVC(`{"id": "vc-right", "credentialSubject": {"patientId": "999"}}`),
	}

	result, err := pe.Select(pd, wallet, pe.WithSelectionTrace())
	if err != nil {
		panic(err)
	}

	report := result.Report
	fmt.Println(report.Outcome)
	descriptor := report.Descriptors[0]
	fmt.Println(descriptor.SelectedID)
	dismissed := descriptor.Considered[0]
	fmt.Println(dismissed.CredentialID, dismissed.Dismissal.Reason)
	// Output:
	// matched
	// vc-right
	// vc-wrong constraint_filter
}

// Two-VP composition: build the first presentation, filter its captured bindings down to the
// field ids of the second PD, and seed the second selection with the survivors, so both
// presentations agree on the shared identity.
func ExampleSelect_twoVpComposition() {
	orgPD := mustParsePD(`{
		"id": "org-pd",
		"input_descriptors": [
			{"id": "org", "constraints": {"fields": [{"id": "org_did", "path": ["$.credentialSubject.orgDid"]}]}}
		]
	}`)
	spPD := mustParsePD(`{
		"id": "sp-pd",
		"input_descriptors": [
			{"id": "delegation", "constraints": {"fields": [{"id": "org_did", "path": ["$.credentialSubject.issuedTo"]}]}}
		]
	}`)
	orgWallet := []vc.VerifiableCredential{
		mustParseVC(`{"id": "org-1", "credentialSubject": {"orgDid": "did:web:org"}}`),
	}
	spWallet := []vc.VerifiableCredential{
		mustParseVC(`{"id": "delegation-other", "credentialSubject": {"issuedTo": "did:web:other"}}`),
		mustParseVC(`{"id": "delegation-org", "credentialSubject": {"issuedTo": "did:web:org"}}`),
	}

	orgResult, err := pe.Select(orgPD, orgWallet)
	if err != nil {
		panic(err)
	}

	// caller-side filter: keep only the captured bindings that are field ids on the SP PD
	spFieldIDs := map[string]bool{"org_did": true}
	seed := make(map[string]string)
	for key, value := range orgResult.Bindings {
		if spFieldIDs[key] {
			seed[key] = value
		}
	}

	spResult, err := pe.Select(spPD, spWallet, pe.WithInitialBindings(seed))
	if err != nil {
		panic(err)
	}

	fmt.Println(spResult.Candidates[0].VC.ID.String())
	// Output: delegation-org
}
