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
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
)

func TestKeyResolver_ResolveKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	resolver := NewMockDIDResolver(ctrl)
	keyResolver := DIDKeyResolver{Resolver: resolver}

	doc := newDidDoc()
	resolver.EXPECT().Resolve(doc.ID, gomock.Any()).AnyTimes().Return(&doc, nil, nil)

	t.Run("ok - it finds the key", func(t *testing.T) {
		keyId, key, err := keyResolver.ResolveKey(doc.ID, nil, AssertionMethod)
		require.NoError(t, err)
		assert.Equal(t, doc.VerificationMethod[0].ID.URI(), keyId)
		assert.NotNil(t, key)
	})

	t.Run("error - document not found", func(t *testing.T) {
		unknownDID := did.MustParseDID("did:example:123")
		resolver.EXPECT().Resolve(unknownDID, gomock.Any()).Return(nil, nil, ErrNotFound)
		keyId, key, err := keyResolver.ResolveKey(unknownDID, nil, AssertionMethod)
		assert.EqualError(t, err, "unable to find the DID document")
		assert.Empty(t, keyId)
		assert.Nil(t, key)
	})

	t.Run("error - key not found", func(t *testing.T) {
		keyId, key, err := keyResolver.ResolveKey(did.MustParseDIDURL(doc.ID.String()), nil, CapabilityDelegation)
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

func TestKeyResolver_ResolveKeyByID(t *testing.T) {
	ctrl := gomock.NewController(t)
	resolver := NewMockDIDResolver(ctrl)
	keyResolver := DIDKeyResolver{Resolver: resolver}
	doc := newDidDoc()
	resolver.EXPECT().Resolve(doc.ID, gomock.Any()).AnyTimes().Return(&doc, nil, nil)
	keyID := doc.VerificationMethod[0].ID

	t.Run("ok - it finds the key", func(t *testing.T) {
		key, err := keyResolver.ResolveKeyByID(keyID.String(), nil, AssertionMethod)
		assert.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("error - invalid key ID", func(t *testing.T) {
		key, err := keyResolver.ResolveKeyByID("abcdef", nil, AssertionMethod)
		assert.EqualError(t, err, "invalid key ID (id=abcdef): invalid DID")
		assert.Nil(t, key)
	})

	t.Run("error - document not found", func(t *testing.T) {
		unknownDID := did.MustParseDIDURL("did:example:123")
		resolver.EXPECT().Resolve(unknownDID, gomock.Any()).Return(nil, nil, ErrNotFound)
		key, err := keyResolver.ResolveKeyByID(unknownDID.String()+"#456", nil, AssertionMethod)
		assert.EqualError(t, err, "unable to find the DID document")
		assert.Nil(t, key)
	})

	t.Run("error - key not found", func(t *testing.T) {
		key, err := keyResolver.ResolveKeyByID(did.MustParseDIDURL(doc.ID.String()+"#123").String(), nil, AssertionMethod)
		assert.EqualError(t, err, "key not found in DID document")
		assert.Nil(t, key)
	})

	t.Run("error - unknown relationship type", func(t *testing.T) {
		key, err := keyResolver.ResolveKeyByID(keyID.String(), nil, 1000)
		assert.EqualError(t, err, "unable to locate RelationType 1000")
		assert.Nil(t, key)
	})
}
