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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

var holder = *TestDIDA

func TestResolveSigningKey(t *testing.T) {
	resolver := NewTestVDRInstance(io.TestDirectory(t))
	resolver.Configure(core.ServerConfig{})
	keyResolver := VDRKeyResolver{VDR: resolver}

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
	keyResolver := VDRKeyResolver{VDR: resolver}

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
