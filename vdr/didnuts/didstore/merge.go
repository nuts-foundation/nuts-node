/*
 * Copyright (C) 2022 Nuts community
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

package didstore

import (
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/util"
	"sort"
	"strings"

	"github.com/nuts-foundation/go-did/did"
)

// mergeDocuments merges two DID Documents that share the same ID
func mergeDocuments(docA did.Document, docB did.Document) did.Document {
	result := &did.Document{}
	docs := []did.Document{docA, docB}

	mergeBasics(docs, result)
	mergeKeys(docs, result)
	mergeControllers(docs, result)
	mergeServices(docs, result)

	// for consistent results
	sort.Slice(result.Context, contextSort(result))
	sort.Slice(result.Service, serviceSort(result))
	sort.Slice(result.VerificationMethod, verificationMethodSort(result))
	sort.Slice(result.KeyAgreement, keyAgreementSort(result))
	sort.Slice(result.AssertionMethod, assertionSort(result))
	sort.Slice(result.Authentication, authenticationSort(result))
	sort.Slice(result.CapabilityInvocation, capabilityInvocationSort(result))
	sort.Slice(result.CapabilityDelegation, capabilityDelegationSort(result))

	return *result
}

func mergeBasics(docs []did.Document, result *did.Document) {
	// ID
	result.ID = docs[0].ID

	// context
	contexts := map[string]interface{}{}
	for _, doc := range docs {
		for _, context := range doc.Context {
			if contextStr := util.LDContextToString(context); contextStr != "" {
				contexts[contextStr] = context
			}
		}
	}
	for _, context := range contexts {
		result.Context = append(result.Context, context)
	}
}

// mergeKeys merges keys based upon their ID. The ID is derived from the public key.
func mergeKeys(docs []did.Document, result *did.Document) {
	// VerificationMethod holds the actual keys
	verificationMethods := map[string]*did.VerificationMethod{}
	// different VerificationRelationShips
	authentications := map[string]did.VerificationRelationship{}
	assertions := map[string]did.VerificationRelationship{}
	capabilityInvocations := map[string]did.VerificationRelationship{}
	capabilityDelegations := map[string]did.VerificationRelationship{}
	keyAgreements := map[string]did.VerificationRelationship{}

	for _, doc := range docs {
		for _, verificationMethod := range doc.VerificationMethod {
			verificationMethods[verificationMethod.ID.String()] = verificationMethod
		}
		for _, authentication := range doc.Authentication {
			authentications[authentication.ID.String()] = authentication
		}
		for _, assertion := range doc.AssertionMethod {
			assertions[assertion.ID.String()] = assertion
		}
		for _, capabilityInvocation := range doc.CapabilityInvocation {
			capabilityInvocations[capabilityInvocation.ID.String()] = capabilityInvocation
		}
		for _, capabilityDelegation := range doc.CapabilityDelegation {
			capabilityDelegations[capabilityDelegation.ID.String()] = capabilityDelegation
		}
		for _, keyAgreement := range doc.KeyAgreement {
			keyAgreements[keyAgreement.ID.String()] = keyAgreement
		}
	}
	// verificationMethods from set
	for _, verificationMethod := range verificationMethods {
		result.VerificationMethod = append(result.VerificationMethod, verificationMethod)
	}
	// for consistent results
	sort.Slice(result.VerificationMethod, func(i, j int) bool {
		is := result.VerificationMethod[i].ID.String()
		js := result.VerificationMethod[j].ID.String()
		return strings.Compare(is, js) == -1
	})
	// same for all relationships
	for _, relation := range authentications {
		result.Authentication = append(result.Authentication, relation)
	}
	for _, relation := range assertions {
		result.AssertionMethod = append(result.AssertionMethod, relation)
	}
	for _, relation := range capabilityInvocations {
		result.CapabilityInvocation = append(result.CapabilityInvocation, relation)
	}
	for _, relation := range capabilityDelegations {
		result.CapabilityDelegation = append(result.CapabilityDelegation, relation)
	}
	for _, relation := range keyAgreements {
		result.KeyAgreement = append(result.KeyAgreement, relation)
	}
}

func mergeControllers(docs []did.Document, result *did.Document) {
	controllers := map[string]did.DID{}
	for _, doc := range docs {
		for _, controller := range doc.Controller {
			controllers[controller.String()] = controller
		}
	}
	for _, controller := range controllers {
		result.Controller = append(result.Controller, controller)
	}
}

// mergeServices merges services based upon their ID. The ID is derived from the contents. Two services sharing the same ID have the same contents.
func mergeServices(docs []did.Document, result *did.Document) {
	services := map[string]did.Service{}
	for _, doc := range docs {
		for _, service := range doc.Service {
			services[service.ID.String()] = service
		}
	}
	for _, service := range services {
		result.Service = append(result.Service, service)
	}
}

type less func(i, j int) bool

func verificationMethodSort(result *did.Document) less {
	return func(i, j int) bool {
		is := result.VerificationMethod[i].ID.String()
		js := result.VerificationMethod[j].ID.String()
		return strings.Compare(is, js) == -1
	}
}

func keyAgreementSort(result *did.Document) less {
	return func(i, j int) bool {
		is := result.KeyAgreement[i].ID.String()
		js := result.KeyAgreement[j].ID.String()
		return strings.Compare(is, js) == -1
	}
}

func assertionSort(result *did.Document) less {
	return func(i, j int) bool {
		is := result.AssertionMethod[i].ID.String()
		js := result.AssertionMethod[j].ID.String()
		return strings.Compare(is, js) == -1
	}
}

func authenticationSort(result *did.Document) less {
	return func(i, j int) bool {
		is := result.Authentication[i].ID.String()
		js := result.Authentication[j].ID.String()
		return strings.Compare(is, js) == -1
	}
}

func capabilityInvocationSort(result *did.Document) less {
	return func(i, j int) bool {
		is := result.CapabilityInvocation[i].ID.String()
		js := result.CapabilityInvocation[j].ID.String()
		return strings.Compare(is, js) == -1
	}
}

func capabilityDelegationSort(result *did.Document) less {
	return func(i, j int) bool {
		is := result.CapabilityDelegation[i].ID.String()
		js := result.CapabilityDelegation[j].ID.String()
		return strings.Compare(is, js) == -1
	}
}

func serviceSort(result *did.Document) less {
	return func(i, j int) bool {
		is := result.Service[i].ID.String()
		js := result.Service[j].ID.String()
		return strings.Compare(is, js) == -1
	}
}

func contextSort(result *did.Document) less {
	return func(i, j int) bool {
		is := util.LDContextToString(result.Context[i])
		js := util.LDContextToString(result.Context[j])
		return strings.Compare(is, js) == -1
	}
}
