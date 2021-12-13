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
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"

	"github.com/google/uuid"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/stretchr/testify/assert"
)

func TestGenerateID(t *testing.T) {
	issuer, _ := ssi.ParseURI(vdr.TestDIDA.String())
	id := generateID(*issuer)

	if !assert.NotNil(t, id) {
		return
	}

	assert.Contains(t, id.String(), vdr.TestDIDA.String())

	_, err := uuid.Parse(id.Fragment)

	assert.NoError(t, err)
}

func TestDefaultBuilder_Type(t *testing.T) {
	b := defaultBuilder{vcType: "type"}

	assert.Equal(t, "type", b.Type())
}

func TestDefaultBuilder_Fill(t *testing.T) {
	b := defaultBuilder{vcType: "type"}
	issuer, _ := ssi.ParseURI(vdr.TestDIDA.String())
	subject := &vc.VerifiableCredential{
		Issuer: *issuer,
	}
	defer func() {
		nowFunc = time.Now
	}()
	checkTime := time.Now()
	nowFunc = func() time.Time {
		return checkTime
	}

	b.Fill(subject)

	t.Run("adds context", func(t *testing.T) {
		assert.True(t, subject.ContainsContext(vc.VCContextV1URI()))
		assert.True(t, subject.ContainsContext(*NutsContextURI))
	})

	t.Run("adds type", func(t *testing.T) {
		vcType, _ := ssi.ParseURI("type")
		assert.True(t, subject.IsType(vc.VerifiableCredentialTypeV1URI()))
		assert.True(t, subject.IsType(*vcType))
	})

	t.Run("adds issuanceDate", func(t *testing.T) {
		assert.NotEqual(t, time.Time{}, subject.IssuanceDate)
	})

	t.Run("adds ID", func(t *testing.T) {
		assert.NotNil(t, subject.ID)
	})

	t.Run("sets time", func(t *testing.T) {
		assert.Equal(t, checkTime, subject.IssuanceDate)
	})

	t.Run("default VC type is not added twice if already present", func(t *testing.T) {
		subject := &vc.VerifiableCredential{
			Type:   []ssi.URI{vc.VerifiableCredentialTypeV1URI()},
			Issuer: *issuer,
		}
		b.Fill(subject)
		assert.Len(t, subject.Type, 2)
	})
}
