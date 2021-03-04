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
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/stretchr/testify/assert"
)

func TestGenerateID(t *testing.T) {
	u2, _ := url.Parse(vdr.RandomDID.String())
	issuer := did.URI{URL: *u2}

	id := generateID(issuer)

	if !assert.NotNil(t, id) {
		return
	}

	assert.Contains(t, id.String(), vdr.RandomDID.String())

	_, err := uuid.Parse(id.Fragment)

	assert.NoError(t, err)
}

func TestDefaultBuilder_Type(t *testing.T) {
	b := defaultBuilder{vcType: "type"}

	assert.Equal(t, "type", b.Type())
}

func TestDefaultBuilder_Build(t *testing.T) {
	b := defaultBuilder{vcType: "type"}
	u2, _ := url.Parse(vdr.RandomDID.String())
	issuer := did.URI{URL: *u2}
	vc := &did.VerifiableCredential{
		Issuer: issuer,
	}

	b.Build(vc)

	t.Run("adds context", func(t *testing.T) {
		assert.True(t, containsContext(*vc, DefaultContext))
		assert.True(t, containsContext(*vc, NutsContext))
	})

	t.Run("adds type", func(t *testing.T) {
		assert.True(t, containsType(*vc, DefaultCredentialType))
		assert.True(t, containsType(*vc, "type"))
	})

	t.Run("adds issuanceDate", func(t *testing.T) {
		assert.NotEqual(t, time.Time{}, vc.IssuanceDate)
	})

	t.Run("adds ID", func(t *testing.T) {
		assert.NotNil(t, vc.ID)
	})
}
