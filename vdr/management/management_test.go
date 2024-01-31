/*
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
 *
 */

package management

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
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

func TestCreationOptions_With(t *testing.T) {
	// make sure With() returns a mutated copy
	o := defaultDIDCreationOptions{}
	result := o.With("test")
	require.NotNil(t, result)
	assert.Contains(t, result.All(), "test")
	assert.NotContains(t, o.All(), "test")
}
