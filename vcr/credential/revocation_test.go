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
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"
)

func TestBuildRevocation(t *testing.T) {
	vc := did.VerifiableCredential{}
	vcData, _ := os.ReadFile("../test/vc.json")
	json.Unmarshal(vcData, &vc)


	at := time.Now()
	nowFunc = func() time.Time {
		return at
	}
	defer func() {
		nowFunc = time.Now
	}()

	r := BuildRevocation(vc)

	assert.Equal(t, *vc.ID, r.Subject)
	assert.Equal(t, vc.Issuer, r.Issuer)
	assert.Equal(t, "Revoked", r.CurrentStatus)
	assert.Equal(t, at, r.StatusDate)
}

func TestValidateRevocation(t *testing.T) {
	revocation := Revocation{}
	jData, _ := os.ReadFile("../test/revocation.json")
	json.Unmarshal(jData, &revocation)

	t.Run("ok", func(t *testing.T) {
		assert.NoError(t, ValidateRevocation(revocation))
	})

	t.Run("error - empty subject", func(t *testing.T) {
		r := revocation
		r.Subject = did.URI{}

		err := ValidateRevocation(r)
		assert.Error(t, err)
		assert.Equal(t, "validation failed: 'subject' is required and requires a valid fragment", err.Error())
	})

	t.Run("error - empty subject fragment", func(t *testing.T) {
		r := revocation
		r.Subject.Fragment = ""

		err := ValidateRevocation(r)
		assert.Error(t, err)
		assert.Equal(t, "validation failed: 'subject' is required and requires a valid fragment", err.Error())
	})

	t.Run("error - issuer is required", func(t *testing.T) {
		r := revocation
		r.Issuer = did.URI{}

		err := ValidateRevocation(r)
		assert.Error(t, err)
		assert.Equal(t, "validation failed: 'issuer' is required", err.Error())
	})

	t.Run("error - zero time", func(t *testing.T) {
		r := revocation
		r.StatusDate = time.Time{}

		err := ValidateRevocation(r)
		assert.Error(t, err)
		assert.Equal(t, "validation failed: 'statusDate' is required", err.Error())
	})

	t.Run("error - wrong status", func(t *testing.T) {
		r := revocation
		r.CurrentStatus = "unknown"

		err := ValidateRevocation(r)
		assert.Error(t, err)
		assert.Equal(t, "validation failed: 'currentStatus' is required and must be one of [Revoked]", err.Error())
	})

	t.Run("error - missing proof", func(t *testing.T) {
		r := revocation
		r.Proof = nil

		err := ValidateRevocation(r)
		assert.Error(t, err)
		assert.Equal(t, "validation failed: 'proof' is required", err.Error())
	})
}
