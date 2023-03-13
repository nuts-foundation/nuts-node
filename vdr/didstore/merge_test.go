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
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
)

func TestMerge(t *testing.T) {
	didA, _ := did.ParseDID("did:nuts:A")
	didB, _ := did.ParseDID("did:nuts:B")
	uriA := ssi.MustParseURI("did:nuts:A#A")
	uriB := ssi.MustParseURI("did:nuts:A#B")
	vmA := &did.VerificationMethod{ID: *didA, Type: ssi.JsonWebKey2020}
	vmB := &did.VerificationMethod{ID: *didB, Type: ssi.JsonWebKey2020}
	vrA := &did.VerificationRelationship{VerificationMethod: vmA}
	vrB := &did.VerificationRelationship{VerificationMethod: vmB}
	serviceA := did.Service{ID: uriA, Type: "type A"}
	serviceB := did.Service{ID: uriB, Type: "type B"}

	type test struct {
		title string
		docA  did.Document
		docB  did.Document
		exp   did.Document
	}
	tests := []test{
		{
			"empty",
			did.Document{ID: *didA},
			did.Document{ID: *didA},
			did.Document{ID: *didA},
		},
		{
			"matching context",
			did.Document{ID: *didA, Context: []ssi.URI{did.DIDContextV1URI()}},
			did.Document{ID: *didA, Context: []ssi.URI{did.DIDContextV1URI()}},
			did.Document{ID: *didA, Context: []ssi.URI{did.DIDContextV1URI()}},
		},
		{
			"non-matching context",
			did.Document{ID: *didA, Context: []ssi.URI{did.DIDContextV1URI()}},
			did.Document{ID: *didA, Context: []ssi.URI{did.DIDContextV1URI(), vc.VCContextV1URI()}},
			did.Document{ID: *didA, Context: []ssi.URI{vc.VCContextV1URI(), did.DIDContextV1URI()}},
		},
		{
			"matching service",
			did.Document{ID: *didA, Service: []did.Service{serviceA}},
			did.Document{ID: *didA, Service: []did.Service{serviceA}},
			did.Document{ID: *didA, Service: []did.Service{serviceA}},
		},
		{
			"non-matching service",
			did.Document{ID: *didA, Service: []did.Service{serviceA}},
			did.Document{ID: *didA, Service: []did.Service{serviceA, serviceB}},
			did.Document{ID: *didA, Service: []did.Service{serviceA, serviceB}},
		},
		{
			"matching controllers",
			did.Document{ID: *didA, Controller: []did.DID{*didA}},
			did.Document{ID: *didA, Controller: []did.DID{*didA}},
			did.Document{ID: *didA, Controller: []did.DID{*didA}},
		},
		{
			"non-matching controllers",
			did.Document{ID: *didA, Controller: []did.DID{*didA}},
			did.Document{ID: *didA, Controller: []did.DID{}},
			did.Document{ID: *didA, Controller: []did.DID{*didA}},
		},
		{
			"matching VMs",
			did.Document{ID: *didA, VerificationMethod: []*did.VerificationMethod{vmA}},
			did.Document{ID: *didA, VerificationMethod: []*did.VerificationMethod{vmA}},
			did.Document{ID: *didA, VerificationMethod: []*did.VerificationMethod{vmA}},
		},
		{
			"non-matching VMs",
			did.Document{ID: *didA, VerificationMethod: []*did.VerificationMethod{vmA}},
			did.Document{ID: *didA, VerificationMethod: []*did.VerificationMethod{vmB}},
			did.Document{ID: *didA, VerificationMethod: []*did.VerificationMethod{vmA, vmB}},
		},
		{
			"assertion",
			did.Document{ID: *didA, AssertionMethod: []did.VerificationRelationship{*vrA}},
			did.Document{ID: *didA, AssertionMethod: []did.VerificationRelationship{*vrB}},
			did.Document{ID: *didA, AssertionMethod: []did.VerificationRelationship{*vrA, *vrB}},
		},
		{
			"authentication",
			did.Document{ID: *didA, Authentication: []did.VerificationRelationship{*vrA}},
			did.Document{ID: *didA, Authentication: []did.VerificationRelationship{*vrB}},
			did.Document{ID: *didA, Authentication: []did.VerificationRelationship{*vrA, *vrB}},
		},
		{
			"capabilityInvocation",
			did.Document{ID: *didA, CapabilityInvocation: []did.VerificationRelationship{*vrA}},
			did.Document{ID: *didA, CapabilityInvocation: []did.VerificationRelationship{*vrB}},
			did.Document{ID: *didA, CapabilityInvocation: []did.VerificationRelationship{*vrA, *vrB}},
		},
		{
			"keyAgreement",
			did.Document{ID: *didA, KeyAgreement: []did.VerificationRelationship{*vrA}},
			did.Document{ID: *didA, KeyAgreement: []did.VerificationRelationship{*vrB}},
			did.Document{ID: *didA, KeyAgreement: []did.VerificationRelationship{*vrA, *vrB}},
		},
		{
			"capabilityDelegation",
			did.Document{ID: *didA, CapabilityDelegation: []did.VerificationRelationship{*vrA}},
			did.Document{ID: *didA, CapabilityDelegation: []did.VerificationRelationship{*vrB}},
			did.Document{ID: *didA, CapabilityDelegation: []did.VerificationRelationship{*vrA, *vrB}},
		},
	}

	t.Run("ok", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.title, func(t *testing.T) {
				r := mergeDocuments(test.docA, test.docB)

				assert.Equal(t, test.exp, r)
			})
		}
	})
}
