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

package vdr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

var holder = *TestDIDA

func TestResolveSigningKey(t *testing.T) {
	resolver := NewTestVDRInstance(io.TestDirectory(t))
	resolver.Configure(core.ServerConfig{})
	keyResolver := KeyResolver{DocResolver: resolver}

	t.Run("ok", func(t *testing.T) {
		doc, _ := resolver.Create()
		_, meta, _ := resolver.Resolve(doc.ID, nil)
		keyID := doc.VerificationMethod[0].ID
		doc.AssertionMethod = doc.Authentication
		resolver.Update(doc.ID, meta.Hash, *doc, nil)

		key, err := keyResolver.ResolveSigningKey(keyID.String(), nil)

		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, key)
	})

	t.Run("unable to resolve", func(t *testing.T) {
		fakeDID, _ := ssi.ParseURI("did:nuts:fake")

		_, err := keyResolver.ResolveSigningKey(fakeDID.String(), nil)

		assert.Error(t, err)
	})

	t.Run("signing key not found", func(t *testing.T) {
		doc, _ := resolver.Create()
		keyID := doc.VerificationMethod[0].ID

		_, err := keyResolver.ResolveSigningKey(keyID.String(), nil)

		assert.Error(t, err)
	})

	t.Run("invalid key ID", func(t *testing.T) {
		_, err := keyResolver.ResolveSigningKey("asdasdsa", nil)

		assert.Error(t, err)
	})
}

func TestResolveSigningKeyID(t *testing.T) {
	resolver := NewTestVDRInstance(io.TestDirectory(t))
	resolver.Configure(core.ServerConfig{})
	keyResolver := KeyResolver{DocResolver: resolver}

	t.Run("ok", func(t *testing.T) {
		doc, _ := resolver.Create()
		_, meta, _ := resolver.Resolve(doc.ID, nil)
		keyID := doc.VerificationMethod[0].ID
		doc.AssertionMethod = doc.Authentication
		resolver.Update(doc.ID, meta.Hash, *doc, nil)

		actual, err := keyResolver.ResolveSigningKeyID(doc.ID, nil)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, keyID.String(), actual)
	})

	t.Run("unable to resolve", func(t *testing.T) {

		_, err := keyResolver.ResolveSigningKeyID(holder, nil)
		assert.Error(t, err)
	})

	t.Run("signing key not found", func(t *testing.T) {
		doc, _ := resolver.Create()

		_, err := keyResolver.ResolveSigningKeyID(doc.ID, nil)

		assert.Equal(t, types.ErrKeyNotFound, err)
	})
}

func TestVDRKeyResolver_ResolveAssertionKeyID(t *testing.T) {
	t.Run("ok - resolve a known key", func(t *testing.T) {
		id123, _ := did.ParseDID("did:nuts:123")
		id123keyID, _ := did.ParseDID("did:nuts:123#abc-method1")
		doc := &did.Document{ID: *id123}
		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		method, _ := did.NewVerificationMethod(*id123keyID, ssi.JsonWebKey2020, *id123, pair.PublicKey)
		doc.AddAssertionMethod(method)

		ctrl := gomock.NewController(t)
		vdrResolver := types.NewMockVDR(ctrl)
		keyResolver := KeyResolver{DocResolver: vdrResolver}
		vdrResolver.EXPECT().Resolve(*id123, nil).Return(doc, nil, nil)

		uri, err := keyResolver.ResolveAssertionKeyID(*id123)
		assert.NoError(t, err)
		assert.Equal(t, uri.String(), id123keyID.String())
	})

	t.Run("error - key not part of the document", func(t *testing.T) {
		id123, _ := did.ParseDID("did:nuts:123")
		doc := &did.Document{ID: *id123}

		ctrl := gomock.NewController(t)
		vdrResolver := types.NewMockVDR(ctrl)
		keyResolver := KeyResolver{DocResolver: vdrResolver}
		vdrResolver.EXPECT().Resolve(*id123, nil).Return(doc, nil, nil)

		uri, err := keyResolver.ResolveAssertionKeyID(*id123)
		assert.EqualError(t, err, "key not found in document")
		assert.Empty(t, uri.String())
	})

	t.Run("error - did document not found", func(t *testing.T) {
		id123, _ := did.ParseDID("did:nuts:123")

		ctrl := gomock.NewController(t)
		vdrResolver := types.NewMockVDR(ctrl)
		keyResolver := KeyResolver{DocResolver: vdrResolver}
		vdrResolver.EXPECT().Resolve(*id123, nil).Return(nil, nil, types.ErrNotFound)

		uri, err := keyResolver.ResolveAssertionKeyID(*id123)
		assert.EqualError(t, err, "unable to find the did document")
		assert.Empty(t, uri.String())
	})
}
