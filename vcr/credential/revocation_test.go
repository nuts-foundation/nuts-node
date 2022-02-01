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
	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
)

func TestBuildRevocation(t *testing.T) {
	target := vc.VerifiableCredential{}
	vcData, _ := os.ReadFile("../test/vc.json")
	json.Unmarshal(vcData, &target)

	at := time.Now()
	nowFunc = func() time.Time {
		return at
	}
	defer func() {
		nowFunc = time.Now
	}()

	r := BuildRevocation(target)

	assert.Equal(t, *target.ID, r.Subject)
	assert.Equal(t, target.Issuer, r.Issuer)
	assert.Equal(t, at, r.Date)
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
}

func TestRevocation_Marshalling(t *testing.T) {
	noProofsJson := "{\"date\":\"0001-01-01T00:00:00Z\",\"issuer\":\"\",\"subject\":\"\"}"
	oneProofJson := "{\"date\":\"0001-01-01T00:00:00Z\",\"issuer\":\"\",\"proof\":{\"type\":\"\",\"proofPurpose\":\"\",\"verificationMethod\":\"\",\"created\":\"0001-01-01T00:00:00Z\",\"jws\":\"\"},\"subject\":\"\"}"
	multipleProofsJson := "{\"date\":\"0001-01-01T00:00:00Z\",\"issuer\":\"\",\"proof\":[{\"type\":\"\",\"proofPurpose\":\"\",\"verificationMethod\":\"\",\"created\":\"0001-01-01T00:00:00Z\",\"jws\":\"\"},{\"type\":\"\",\"proofPurpose\":\"\",\"verificationMethod\":\"\",\"created\":\"0001-01-01T00:00:00Z\",\"jws\":\"\"}],\"subject\":\"\"}"

	t.Run("marshal to JSON", func(t *testing.T) {

		t.Run("with no proofs its empty", func(t *testing.T) {
			r := Revocation{Proof: nil}
			revocationAsJSON, err := json.Marshal(r)
			assert.NoError(t, err)
			assert.Equal(t, []byte(noProofsJson), revocationAsJSON)
		})

		t.Run("with one proof its an single value", func(t *testing.T) {
			r := Revocation{Proof: []vc.JSONWebSignature2020Proof{{}}}
			revocationAsJSON, err := json.Marshal(r)
			assert.NoError(t, err)
			assert.Equal(t, []byte(oneProofJson), revocationAsJSON)
		})

		t.Run("with multiple proofs its an array", func(t *testing.T) {
			r := Revocation{Proof: []vc.JSONWebSignature2020Proof{{}, {}}}
			revocationAsJSON, err := json.Marshal(r)
			assert.NoError(t, err)
			assert.Equal(t, []byte(multipleProofsJson), revocationAsJSON)
		})
	})

	t.Run("unmarshal from JSON", func(t *testing.T) {

		t.Run("no proofs", func(t *testing.T) {
			r := Revocation{}
			assert.NoError(t, json.Unmarshal([]byte(noProofsJson), &r))
			assert.Len(t, r.Proof, 0)
		})

		t.Run("one proof", func(t *testing.T) {
			r := Revocation{}
			assert.NoError(t, json.Unmarshal([]byte(oneProofJson), &r))
			assert.Len(t, r.Proof, 1)
		})

		t.Run("multiple proofs", func(t *testing.T) {
			r := Revocation{}
			assert.NoError(t, json.Unmarshal([]byte(multipleProofsJson), &r))
			assert.Len(t, r.Proof, 2)
		})
	})
}
