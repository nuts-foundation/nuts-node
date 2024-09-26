/*
 * Copyright (C) 2024 Nuts community
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

package orm

import (
	"github.com/nuts-foundation/go-did/did"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyUsage_Is(t *testing.T) {
	types := []DIDKeyFlags{AssertionMethodUsage, AuthenticationUsage, CapabilityDelegationUsage, CapabilityInvocationUsage, KeyAgreementUsage}
	t.Run("one usage", func(t *testing.T) {
		for _, usage := range types {
			for _, other := range types {
				if usage == other {
					assert.True(t, usage.Is(other))
					assert.True(t, other.Is(usage)) // assert symmetry
				} else {
					assert.False(t, usage.Is(other))
					assert.False(t, other.Is(usage)) // assert symmetry
				}
			}
		}
	})
	t.Run("multiple usage", func(t *testing.T) {
		value := AssertionMethodUsage | CapabilityDelegationUsage | KeyAgreementUsage
		for _, other := range types {
			switch other {
			case AssertionMethodUsage:
				fallthrough
			case CapabilityDelegationUsage:
				fallthrough
			case KeyAgreementUsage:
				assert.True(t, value.Is(other))
			default:
				assert.False(t, value.Is(other))
			}
		}
	})
}

func Test_verificationMethodToKeyFlags(t *testing.T) {
	vr1 := did.VerificationRelationship{VerificationMethod: &did.VerificationMethod{
		ID: did.MustParseDIDURL("did:method:something#key-1"),
	}}
	vr2 := did.VerificationRelationship{VerificationMethod: &did.VerificationMethod{
		ID: did.MustParseDIDURL("did:method:something#key-2"),
	}}
	t.Run("single-key", func(t *testing.T) {
		t.Run("AssertionMethod", func(t *testing.T) {
			doc := did.Document{AssertionMethod: did.VerificationRelationships{vr1}}
			assert.Equal(t, AssertionMethodUsage, verificationMethodToKeyFlags(doc, vr1.VerificationMethod))
		})
		t.Run("Authentication", func(t *testing.T) {
			doc := did.Document{Authentication: did.VerificationRelationships{vr1}}
			assert.Equal(t, AuthenticationUsage, verificationMethodToKeyFlags(doc, vr1.VerificationMethod))
		})
		t.Run("CapabilityDelegation", func(t *testing.T) {
			doc := did.Document{CapabilityDelegation: did.VerificationRelationships{vr1}}
			assert.Equal(t, CapabilityDelegationUsage, verificationMethodToKeyFlags(doc, vr1.VerificationMethod))
		})
		t.Run("CapabilityInvocation", func(t *testing.T) {
			doc := did.Document{CapabilityInvocation: did.VerificationRelationships{vr1}}
			assert.Equal(t, CapabilityInvocationUsage, verificationMethodToKeyFlags(doc, vr1.VerificationMethod))
		})
		t.Run("KeyAgreement", func(t *testing.T) {
			doc := did.Document{KeyAgreement: did.VerificationRelationships{vr1}}
			assert.Equal(t, KeyAgreementUsage, verificationMethodToKeyFlags(doc, vr1.VerificationMethod))
		})
	})
	t.Run("multi-key", func(t *testing.T) {
		doc := did.Document{
			AssertionMethod:      did.VerificationRelationships{vr1},
			CapabilityInvocation: did.VerificationRelationships{vr1, vr2},
			KeyAgreement:         did.VerificationRelationships{vr2},
		}
		assert.Equal(t, AssertionMethodUsage|CapabilityInvocationUsage, verificationMethodToKeyFlags(doc, vr1.VerificationMethod))
		assert.Equal(t, CapabilityInvocationUsage|KeyAgreementUsage, verificationMethodToKeyFlags(doc, vr2.VerificationMethod))
	})
}
