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
 */

package iam

import (
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
)

func Test_validatePresentationSigner(t *testing.T) {
	signer := did.MustParseDID("did:example:123")
	vp, _ := vc.ParseVerifiablePresentation(`{"proof":[{"verificationMethod":"did:example:123#first-vm"}]}`)
	t.Run("ok - empty presentation", func(t *testing.T) {
		subjectDID, err := validatePresentationSigner(*vp, signer)

		assert.Nil(t, err)
		assert.NotNil(t, subjectDID)
	})
}
