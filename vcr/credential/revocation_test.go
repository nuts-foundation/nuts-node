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

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/stretchr/testify/assert"
)

func TestBuildRevocation(t *testing.T) {
	target := test.ValidNutsOrganizationCredential(t)

	at := time.Now()
	nowFunc = func() time.Time {
		return at
	}
	defer func() {
		nowFunc = time.Now
	}()

	r := BuildRevocation(target.Issuer, *target.ID)

	assert.Equal(t, *target.ID, r.Subject)
	assert.Equal(t, target.Issuer, r.Issuer)
	assert.Equal(t, at, r.Date)
}

func TestValidateRevocation(t *testing.T) {
	t.Run("JSON-LD proof revocations", func(t *testing.T) {
		jData, _ := os.ReadFile("../test/ld-revocation.json")
		revocation := Revocation{}
		json.Unmarshal(jData, &revocation)

		t.Run("ok", func(t *testing.T) {
			assert.NoError(t, ValidateRevocation(revocation))
		})

		t.Run("it failes when the type is incorrect", func(t *testing.T) {
			revocation := Revocation{}
			json.Unmarshal(jData, &revocation)
			revocation.Type = []ssi.URI{}
			assert.EqualError(t, ValidateRevocation(revocation), "validation failed: 'type' does not contain CredentialRevocation")
		})
	})

	t.Run("old style revocations", func(t *testing.T) {
		revocation := Revocation{}
		jData, _ := os.ReadFile("../test/revocation.json")
		json.Unmarshal(jData, &revocation)

		t.Run("ok", func(t *testing.T) {
			assert.NoError(t, ValidateRevocation(revocation))
		})

		t.Run("error - empty subject", func(t *testing.T) {
			r := revocation
			r.Subject = ssi.URI{}

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
			r.Issuer = ssi.URI{}

			err := ValidateRevocation(r)
			assert.Error(t, err)
			assert.Equal(t, "validation failed: 'issuer' is required", err.Error())
		})

		t.Run("error - zero time", func(t *testing.T) {
			r := revocation
			r.Date = time.Time{}

			err := ValidateRevocation(r)
			assert.Error(t, err)
			assert.Equal(t, "validation failed: 'date' is required", err.Error())
		})

		t.Run("error - missing proof", func(t *testing.T) {
			r := revocation
			r.Proof = nil

			err := ValidateRevocation(r)
			assert.Error(t, err)
			assert.Equal(t, "validation failed: 'proof' is required", err.Error())
		})
	})
}
