/*
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

package doc

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_MakeServiceReference(t *testing.T) {
	d, _ := did.ParseDID("did:nuts:abc")
	assert.Equal(t, "did:nuts:abc/serviceEndpoint?type=hello", MakeServiceReference(*d, "hello").String())
}

func Test_IsServiceReference(t *testing.T) {
	assert.True(t, IsServiceReference("did:nuts:bla"))
	assert.False(t, IsServiceReference("nuts:did:not-a-did"))
}

func Test_ValidateServiceReference(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ref := ssi.MustParseURI("did:nuts:abc/serviceEndpoint?type=t")
		err := ValidateServiceReference(ref)
		assert.NoError(t, err)
	})
	t.Run("error - invalid path", func(t *testing.T) {
		ref := ssi.MustParseURI("did:nuts:abc/serviceEndpointWithInvalidPostfix?type=sajdklsad")
		err := ValidateServiceReference(ref)
		assert.ErrorIs(t, err, types.ErrInvalidServiceQuery{})
		assert.ErrorContains(t, err, "URL path must be '/serviceEndpoint'")
	})
	t.Run("error - too many type params", func(t *testing.T) {
		ref := ssi.MustParseURI("did:nuts:abc/serviceEndpoint?type=t1&type=t2")
		err := ValidateServiceReference(ref)
		assert.ErrorIs(t, err, types.ErrInvalidServiceQuery{})
		assert.ErrorContains(t, err, "URL must contain exactly one 'type' query parameter, with exactly one value")
	})
	t.Run("error - no type params", func(t *testing.T) {
		ref := ssi.MustParseURI("did:nuts:abc/serviceEndpoint")
		err := ValidateServiceReference(ref)
		assert.ErrorIs(t, err, types.ErrInvalidServiceQuery{})
		assert.ErrorContains(t, err, "URL must contain exactly one 'type' query parameter, with exactly one value")
	})
	t.Run("error - invalid params", func(t *testing.T) {
		ref := ssi.MustParseURI("did:nuts:abc/serviceEndpoint?type=t1&someOther=not-allowed")
		err := ValidateServiceReference(ref)
		assert.ErrorIs(t, err, types.ErrInvalidServiceQuery{})
		assert.ErrorContains(t, err, "URL must contain exactly one 'type' query parameter, with exactly one value")
	})
}
