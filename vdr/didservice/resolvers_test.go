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

package didservice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
)

func TestServiceResolver_Resolve(t *testing.T) {
	meta := &types.DocumentMetadata{Hash: hash.EmptyHash()}

	didA, _ := did.ParseDID("did:nuts:A")
	didB, _ := did.ParseDID("did:nuts:B")

	serviceID := ssi.MustParseURI(fmt.Sprintf("%s#1", didA.String()))
	docA := did.Document{
		Context: []ssi.URI{did.DIDContextV1URI()},
		ID:      *didA,
		Service: []did.Service{{
			ID:              serviceID,
			Type:            "hello",
			ServiceEndpoint: "http://hello",
		}},
	}
	docB := did.Document{
		Context: []ssi.URI{did.DIDContextV1URI()},
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
		resolver := types.NewMockDIDResolver(ctrl)

		resolver.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)

		actual, err := ServiceResolver{Resolver: resolver}.Resolve(MakeServiceReference(*didB, "simple"), DefaultMaxServiceReferenceDepth)

		assert.NoError(t, err)
		assert.Equal(t, docB.Service[0], actual)
	})
	t.Run("ok - external", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := types.NewMockDIDResolver(ctrl)

		resolver.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)
		resolver.EXPECT().Resolve(*didA, nil).MinTimes(1).Return(&docA, meta, nil)

		actual, err := ServiceResolver{Resolver: resolver}.Resolve(MakeServiceReference(*didB, "external"), DefaultMaxServiceReferenceDepth)

		assert.NoError(t, err)
		assert.Equal(t, docA.Service[0], actual)
	})
	t.Run("error - cyclic reference (yields refs too deep)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := types.NewMockDIDResolver(ctrl)

		resolver.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)

		actual, err := ServiceResolver{Resolver: resolver}.Resolve(MakeServiceReference(*didB, "cyclic-ref"), DefaultMaxServiceReferenceDepth)

		assert.EqualError(t, err, "service references are nested to deeply before resolving to a non-reference")
		assert.Empty(t, actual)
	})
	t.Run("error - invalid ref", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := types.NewMockDIDResolver(ctrl)

		resolver.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)

		actual, err := ServiceResolver{Resolver: resolver}.Resolve(MakeServiceReference(*didB, "invalid-ref"), DefaultMaxServiceReferenceDepth)

		assert.EqualError(t, err, "DID service query invalid: endpoint URI path must be /serviceEndpoint")
		assert.Empty(t, actual)
	})
	t.Run("error - service not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := types.NewMockDIDResolver(ctrl)

		resolver.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)

		actual, err := ServiceResolver{Resolver: resolver}.Resolve(MakeServiceReference(*didB, "non-existent"), DefaultMaxServiceReferenceDepth)

		assert.EqualError(t, err, "service not found in DID Document")
		assert.Empty(t, actual)
	})
	t.Run("error - DID not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := types.NewMockDIDResolver(ctrl)

		resolver.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(nil, nil, types.ErrNotFound)

		actual, err := ServiceResolver{Resolver: resolver}.Resolve(MakeServiceReference(*didB, "non-existent"), DefaultMaxServiceReferenceDepth)

		assert.EqualError(t, err, "unable to find the DID document")
		assert.Empty(t, actual)
	})

}

func TestKeyResolver_ResolveKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	resolver := types.NewMockDIDResolver(ctrl)
	keyResolver := KeyResolver{Resolver: resolver}

	doc := newDidDoc()
	resolver.EXPECT().Resolve(doc.ID, gomock.Any()).AnyTimes().Return(&doc, nil, nil)

	t.Run("ok - it finds the key", func(t *testing.T) {
		keyId, key, err := keyResolver.ResolveKey(doc.ID, nil, types.AssertionMethod)
		require.NoError(t, err)
		assert.Equal(t, doc.VerificationMethod[0].ID.URI(), keyId)
		assert.NotNil(t, key)
	})

	t.Run("error - document not found", func(t *testing.T) {
		unknownDID := did.MustParseDID("did:example:123")
		resolver.EXPECT().Resolve(unknownDID, gomock.Any()).Return(nil, nil, types.ErrNotFound)
		keyId, key, err := keyResolver.ResolveKey(unknownDID, nil, types.AssertionMethod)
		assert.EqualError(t, err, "unable to find the DID document")
		assert.Empty(t, keyId)
		assert.Nil(t, key)
	})

	t.Run("error - key not found", func(t *testing.T) {
		keyId, key, err := keyResolver.ResolveKey(did.MustParseDIDURL(doc.ID.String()), nil, types.CapabilityDelegation)
		assert.EqualError(t, err, "key not found in DID document")
		assert.Empty(t, keyId)
		assert.Nil(t, key)
	})

	t.Run("error - unknown relationship type", func(t *testing.T) {
		keyId, key, err := keyResolver.ResolveKey(doc.ID, nil, 1000)
		assert.EqualError(t, err, "unable to locate RelationType 1000")
		assert.Empty(t, keyId)
		assert.Nil(t, key)
	})
}

func newDidDoc() did.Document {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := did.MustParseDID("did:example:sakjsakldjsakld")
	keyID := id
	keyID.Fragment = "key-1"
	vm, _ := did.NewVerificationMethod(keyID, ssi.JsonWebKey2020, id, privateKey.Public())
	doc := did.Document{
		ID: id,
	}
	doc.AddAssertionMethod(vm)
	return doc
}

func TestKeyResolver_ResolveKeyByID(t *testing.T) {
	ctrl := gomock.NewController(t)
	resolver := types.NewMockDIDResolver(ctrl)
	keyResolver := KeyResolver{Resolver: resolver}
	doc := newDidDoc()
	resolver.EXPECT().Resolve(doc.ID, gomock.Any()).AnyTimes().Return(&doc, nil, nil)
	keyID := doc.VerificationMethod[0].ID

	t.Run("ok - it finds the key", func(t *testing.T) {
		key, err := keyResolver.ResolveKeyByID(keyID.String(), nil, types.AssertionMethod)
		assert.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("error - invalid key ID", func(t *testing.T) {
		key, err := keyResolver.ResolveKeyByID("abcdef", nil, types.AssertionMethod)
		assert.EqualError(t, err, "invalid key ID (id=abcdef): invalid DID")
		assert.Nil(t, key)
	})

	t.Run("error - document not found", func(t *testing.T) {
		unknownDID := did.MustParseDIDURL("did:example:123")
		resolver.EXPECT().Resolve(unknownDID, gomock.Any()).Return(nil, nil, types.ErrNotFound)
		key, err := keyResolver.ResolveKeyByID(unknownDID.String()+"#456", nil, types.AssertionMethod)
		assert.EqualError(t, err, "unable to find the DID document")
		assert.Nil(t, key)
	})

	t.Run("error - key not found", func(t *testing.T) {
		key, err := keyResolver.ResolveKeyByID(did.MustParseDIDURL(doc.ID.String()+"#123").String(), nil, types.AssertionMethod)
		assert.EqualError(t, err, "key not found in DID document")
		assert.Nil(t, key)
	})

	t.Run("error - unknown relationship type", func(t *testing.T) {
		key, err := keyResolver.ResolveKeyByID(keyID.String(), nil, 1000)
		assert.EqualError(t, err, "unable to locate RelationType 1000")
		assert.Nil(t, key)
	})
}

func TestIsFunctionalResolveError(t *testing.T) {
	assert.True(t, IsFunctionalResolveError(types.ErrNotFound))
	assert.True(t, IsFunctionalResolveError(types.ErrDeactivated))
	assert.True(t, IsFunctionalResolveError(types.ErrServiceNotFound))
	assert.True(t, IsFunctionalResolveError(types.ErrServiceReferenceToDeep))
	assert.True(t, IsFunctionalResolveError(types.ErrNoActiveController))
	assert.True(t, IsFunctionalResolveError(did.InvalidDIDErr))
	assert.True(t, IsFunctionalResolveError(ServiceQueryError{Err: errors.New("oops")}))

	assert.False(t, IsFunctionalResolveError(errors.New("some error")))
	assert.False(t, IsFunctionalResolveError(types.ErrDuplicateService))
}
