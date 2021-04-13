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

package doc

import (
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/store"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/vdr/types"
)

func TestResolveSigningKey(t *testing.T) {
	didStore := store.NewMemoryStore()
	keyResolver := KeyResolver{Store: didStore}
	keyCreator := &mockKeyCreator{t: t, jwkStr: jwkString}
	docCreator := Creator{KeyCreator: keyCreator}
	doc, _ := docCreator.Create()
	doc.AddAssertionMethod(doc.VerificationMethod[0])
	didStore.Write(*doc, types.DocumentMetadata{})

	t.Run("ok", func(t *testing.T) {
		key, err := keyResolver.ResolveSigningKey(kid, nil)

		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, key)
	})

	t.Run("unable to resolve document", func(t *testing.T) {
		fakeDID, _ := ssi.ParseURI("did:nuts:fake")

		_, err := keyResolver.ResolveSigningKey(fakeDID.String(), nil)

		assert.Error(t, err)
		assert.Equal(t, types.ErrNotFound, err)
	})

	t.Run("signing key not found in document", func(t *testing.T) {
		_, err := keyResolver.ResolveSigningKey(kid[:len(kid)-2], nil)

		assert.Error(t, err)
		assert.Equal(t, types.ErrKeyNotFound, err)
	})

	t.Run("invalid key ID", func(t *testing.T) {
		_, err := keyResolver.ResolveSigningKey("asdasdsa", nil)

		assert.Error(t, err)
		assert.EqualError(t, err, "invalid key ID (id=asdasdsa): input does not begin with 'did:' prefix")
	})
}

func TestResolveSigningKeyID(t *testing.T) {
	didStore := store.NewMemoryStore()
	keyResolver := KeyResolver{Store: didStore}
	keyCreator := &mockKeyCreator{t: t, jwkStr: jwkString}
	docCreator := Creator{KeyCreator: keyCreator}
	doc, _ := docCreator.Create()
	doc.AddAssertionMethod(doc.VerificationMethod[0])
	didStore.Write(*doc, types.DocumentMetadata{})

	t.Run("ok", func(t *testing.T) {
		actual, err := keyResolver.ResolveSigningKeyID(doc.ID, nil)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, kid, actual)
	})

	t.Run("unable to resolve", func(t *testing.T) {
		did, _ := did.ParseDID("did:nuts:a")

		_, err := keyResolver.ResolveSigningKeyID(*did, nil)

		assert.Error(t, err)
		assert.Equal(t, types.ErrNotFound, err)
	})

	t.Run("signing key not found", func(t *testing.T) {
		did2, _ := did.ParseDID("did:nuts:a")
		doc2 := *doc
		doc2.ID = *did2
		doc2.AssertionMethod = did.VerificationRelationships{}
		err := didStore.Write(doc2, types.DocumentMetadata{})
		if !assert.NoError(t, err) {
			return
		}

		_, err = keyResolver.ResolveSigningKeyID(*did2, nil)

		assert.Equal(t, types.ErrKeyNotFound, err)
	})
}

func TestVDRKeyResolver_ResolveAssertionKeyID(t *testing.T) {
	didStore := store.NewMemoryStore()
	keyResolver := KeyResolver{Store: didStore}
	keyCreator := &mockKeyCreator{t: t, jwkStr: jwkString}
	docCreator := Creator{KeyCreator: keyCreator}
	doc, _ := docCreator.Create()
	doc.AddAssertionMethod(doc.VerificationMethod[0])
	didStore.Write(*doc, types.DocumentMetadata{})

	t.Run("ok - resolve a known key", func(t *testing.T) {
		actual, err := keyResolver.ResolveAssertionKeyID(doc.ID)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, kid, actual.String())
	})

	t.Run("unable to resolve", func(t *testing.T) {
		did, _ := did.ParseDID("did:nuts:a")

		_, err := keyResolver.ResolveAssertionKeyID(*did)

		assert.Error(t, err)
		assert.Equal(t, types.ErrNotFound, err)
	})

	t.Run("signing key not found", func(t *testing.T) {
		did2, _ := did.ParseDID("did:nuts:a")
		doc2 := *doc
		doc2.ID = *did2
		doc2.AssertionMethod = did.VerificationRelationships{}
		err := didStore.Write(doc2, types.DocumentMetadata{})
		if !assert.NoError(t, err) {
			return
		}

		_, err = keyResolver.ResolveAssertionKeyID(*did2)

		assert.Equal(t, types.ErrKeyNotFound, err)
	})
}

func TestResolver_Resolve(t *testing.T) {
	didStore := store.NewMemoryStore()
	resolver := Resolver{Store: didStore}
	keyCreator := &mockKeyCreator{t: t, jwkStr: jwkString}
	docCreator := Creator{KeyCreator: keyCreator}
	doc, _ := docCreator.Create()
	doc.AddAssertionMethod(doc.VerificationMethod[0])
	didStore.Write(*doc, types.DocumentMetadata{})

	t.Run("ok", func(t *testing.T) {
		resultDoc, _, err := resolver.Resolve(doc.ID, nil)

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, doc.ID, resultDoc.ID)
	})
}

func TestKeyResolver_ResolvePublicKey(t *testing.T) {
	didStore := store.NewMemoryStore()
	keyResolver := KeyResolver{Store: didStore}
	keyCreator := &mockKeyCreator{t: t, jwkStr: jwkString}
	docCreator := Creator{KeyCreator: keyCreator}
	doc, _ := docCreator.Create()
	doc.AddAssertionMethod(doc.VerificationMethod[0])
	didStore.Write(*doc, types.DocumentMetadata{})

	t.Run("ok", func(t *testing.T) {
		key, err := keyResolver.ResolvePublicKey(kid, nil)

		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, key)
	})

	t.Run("error - invalid kid", func(t *testing.T) {
		key, err := keyResolver.ResolvePublicKey("not_a_did", nil)

		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("error - unknown did", func(t *testing.T) {
		_, err := keyResolver.ResolvePublicKey("did:nuts:a", nil)

		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, types.ErrNotFound, err)
	})

	t.Run("error - unknown key in document", func(t *testing.T) {
		_, err := keyResolver.ResolvePublicKey(kid[:len(kid)-2], nil)

		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, types.ErrKeyNotFound, err)
	})
}
