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

package resolver

import (
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
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

func TestServiceResolver_Resolve(t *testing.T) {
	meta := &DocumentMetadata{Hash: hash.EmptyHash()}

	didA, _ := did.ParseDID("did:nuts:A")
	didB, _ := did.ParseDID("did:nuts:B")

	serviceID := ssi.MustParseURI(fmt.Sprintf("%s#1", didA.String()))
	docA := did.Document{
		Context: []interface{}{did.DIDContextV1URI()},
		ID:      *didA,
		Service: []did.Service{{
			ID:              serviceID,
			Type:            "hello",
			ServiceEndpoint: "http://hello",
		}},
	}
	docB := did.Document{
		Context: []interface{}{did.DIDContextV1URI()},
		ID:      *didA,
		Service: []did.Service{
			{
				Type:            "simple",
				ServiceEndpoint: "http://world",
			},
			{
				Type:            "cyclic-ref",
				ServiceEndpoint: didB.String() + "/serviceEndpoint?type=cyclic-ref",
			},
			{
				Type:            "invalid-ref",
				ServiceEndpoint: didB.String() + "?type=invalid-ref",
			},
			{
				Type:            "external",
				ServiceEndpoint: MakeServiceReference(docA.ID, "hello").String(),
			},
		},
	}

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := NewMockDIDResolver(ctrl)

		resolver.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)

		actual, err := DIDServiceResolver{Resolver: resolver}.Resolve(MakeServiceReference(*didB, "simple"), DefaultMaxServiceReferenceDepth)

		assert.NoError(t, err)
		assert.Equal(t, docB.Service[0], actual)
	})
	t.Run("ok - external", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := NewMockDIDResolver(ctrl)

		resolver.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)
		resolver.EXPECT().Resolve(*didA, nil).MinTimes(1).Return(&docA, meta, nil)

		actual, err := DIDServiceResolver{Resolver: resolver}.Resolve(MakeServiceReference(*didB, "external"), DefaultMaxServiceReferenceDepth)

		assert.NoError(t, err)
		assert.Equal(t, docA.Service[0], actual)
	})
	t.Run("error - cyclic reference (yields refs too deep)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := NewMockDIDResolver(ctrl)

		resolver.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)

		actual, err := DIDServiceResolver{Resolver: resolver}.Resolve(MakeServiceReference(*didB, "cyclic-ref"), DefaultMaxServiceReferenceDepth)

		assert.EqualError(t, err, "service references are nested to deeply before resolving to a non-reference")
		assert.Empty(t, actual)
	})
	t.Run("error - invalid ref", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := NewMockDIDResolver(ctrl)

		resolver.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)

		actual, err := DIDServiceResolver{Resolver: resolver}.Resolve(MakeServiceReference(*didB, "invalid-ref"), DefaultMaxServiceReferenceDepth)

		assert.EqualError(t, err, "DID service query invalid: endpoint URI path must be /serviceEndpoint")
		assert.Empty(t, actual)
	})
	t.Run("error - service not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := NewMockDIDResolver(ctrl)

		resolver.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)

		actual, err := DIDServiceResolver{Resolver: resolver}.Resolve(MakeServiceReference(*didB, "non-existent"), DefaultMaxServiceReferenceDepth)

		assert.EqualError(t, err, "service not found in DID Document")
		assert.Empty(t, actual)
	})
	t.Run("error - DID not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := NewMockDIDResolver(ctrl)

		resolver.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(nil, nil, ErrNotFound)

		actual, err := DIDServiceResolver{Resolver: resolver}.Resolve(MakeServiceReference(*didB, "non-existent"), DefaultMaxServiceReferenceDepth)

		assert.EqualError(t, err, "unable to find the DID document")
		assert.Empty(t, actual)
	})
}
