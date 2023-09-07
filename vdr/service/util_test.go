/*
 * Copyright (C) 2022 Nuts community
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

package service

import (
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
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
		assert.ErrorAs(t, err, new(ServiceQueryError))
		assert.ErrorContains(t, err, "DID service query invalid")
		assert.ErrorContains(t, err, "endpoint URI path must be /serviceEndpoint")
	})
	t.Run("error - too many type params", func(t *testing.T) {
		ref := ssi.MustParseURI("did:nuts:abc/serviceEndpoint?type=t1&type=t2")
		err := ValidateServiceReference(ref)
		assert.ErrorAs(t, err, new(ServiceQueryError))
		assert.ErrorContains(t, err, "DID service query invalid")
		assert.ErrorContains(t, err, "endpoint URI with multiple type query parameters")
	})
	t.Run("error - no type params", func(t *testing.T) {
		ref := ssi.MustParseURI("did:nuts:abc/serviceEndpoint")
		err := ValidateServiceReference(ref)
		assert.ErrorAs(t, err, new(ServiceQueryError))
		assert.ErrorContains(t, err, "DID service query invalid")
		assert.ErrorContains(t, err, "endpoint URI without type query parameter")
	})
	t.Run("error - invalid params", func(t *testing.T) {
		ref := ssi.MustParseURI("did:nuts:abc/serviceEndpoint?type=t1&someOther=not-allowed")
		err := ValidateServiceReference(ref)
		assert.ErrorAs(t, err, new(ServiceQueryError))
		assert.ErrorContains(t, err, "DID service query invalid")
		assert.ErrorContains(t, err, "endpoint URI with query parameter other than type")
	})
}

func TestGetDIDFromURL(t *testing.T) {
	t.Run("just it", func(t *testing.T) {
		actual, err := GetDIDFromURL("did:nuts:abc")
		assert.NoError(t, err)
		assert.Equal(t, "did:nuts:abc", actual.String())
	})
	t.Run("with path", func(t *testing.T) {
		actual, err := GetDIDFromURL("did:nuts:abc/serviceEndpoint")
		assert.NoError(t, err)
		assert.Equal(t, "did:nuts:abc", actual.String())
	})
	t.Run("with fragment", func(t *testing.T) {
		actual, err := GetDIDFromURL("did:nuts:abc#key-1")
		assert.NoError(t, err)
		assert.Equal(t, "did:nuts:abc", actual.String())
	})
	t.Run("with params", func(t *testing.T) {
		actual, err := GetDIDFromURL("did:nuts:abc?foo=bar")
		assert.NoError(t, err)
		assert.Equal(t, "did:nuts:abc", actual.String())
	})
	t.Run("invalid DID", func(t *testing.T) {
		_, err := GetDIDFromURL("https://example.com")
		assert.Error(t, err)
	})
}
