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
	"testing"

	"github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"
)

func TestFindValidatorAndBuilder(t *testing.T) {
	t.Run("nothing found", func(t *testing.T) {
		v, b := FindValidatorAndBuilder(did.VerifiableCredential{})

		assert.Nil(t, v)
		assert.Nil(t, b)
	})

	t.Run("validator and builder found for NutsOrganizationCredential", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		v, b := FindValidatorAndBuilder(*vc)

		assert.NotNil(t, v)
		assert.NotNil(t, b)
	})
}

func TestExtractTypes(t *testing.T) {
	vc := did.VerifiableCredential{
		Type: []did.URI{did.VerifiableCredentialTypeV1URI(), *NutsOrganizationCredentialTypeURI},
	}

	types := ExtractTypes(vc)

	assert.Len(t, types, 1)
	assert.Equal(t, NutsOrganizationCredentialType, types[0])
}
