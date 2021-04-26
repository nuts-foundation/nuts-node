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

	"github.com/golang/mock/gomock"
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
	docCreator := Creator{KeyStore: keyCreator}
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
	docCreator := Creator{KeyStore: keyCreator}
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

func TestKeyResolver_ResolveAssertionKeyID(t *testing.T) {
	didStore := store.NewMemoryStore()
	keyResolver := KeyResolver{Store: didStore}
	keyCreator := &mockKeyCreator{t: t, jwkStr: jwkString}
	docCreator := Creator{KeyStore: keyCreator}
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
	docCreator := Creator{KeyStore: keyCreator}
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

func TestResolver_ResolveControllers(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")
	id123Method1, _ := did.ParseDID("did:nuts:123#method-1")
	id456, _ := did.ParseDID("did:nuts:456")
	id456Method1, _ := did.ParseDID("did:nuts:456#method-1")
	t.Run("emtpy input", func(t *testing.T) {
		resolver := Resolver{}
		docs, err := resolver.ResolveControllers(did.Document{})
		assert.NoError(t, err)
		assert.Len(t, docs, 0,
			"expected an empty list")
	})

	t.Run("doc is its own controller", func(t *testing.T) {
		resolver := Resolver{}
		doc := did.Document{ID: *id123}
		doc.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})
		docs, err := resolver.ResolveControllers(doc)
		assert.NoError(t, err)
		assert.Len(t, docs, 1,
			"expected the document")
		assert.Equal(t, doc, docs[0])
	})

	t.Run("doc is deactivated", func(t *testing.T) {
		resolver := Resolver{}
		doc := did.Document{ID: *id123}
		docs, err := resolver.ResolveControllers(doc)
		assert.NoError(t, err)
		assert.Len(t, docs, 0,
			"expected an empty list when the document is deactivated")
	})

	t.Run("docA is controller of docB", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := types.NewMockStore(ctrl)

		resolver := Resolver{Store: store}
		docA := did.Document{ID: *id123}
		docA.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})

		store.EXPECT().Resolve(*id123, gomock.Any()).Return(&docA, &types.DocumentMetadata{}, nil)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}

		docs, err := resolver.ResolveControllers(docB)
		assert.NoError(t, err)
		assert.Len(t, docs, 1)
		assert.Equal(t, docA, docs[0],
			"expected docA to be resolved as controller for docB")
	})

	t.Run("docA and docB are both the controllers of docB", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := types.NewMockStore(ctrl)

		resolver := Resolver{Store: store}
		docA := did.Document{ID: *id123}
		docA.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})

		store.EXPECT().Resolve(*id123, gomock.Any()).Return(&docA, &types.DocumentMetadata{}, nil)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123, *id456}}
		docB.AddCapabilityInvocation(&did.VerificationMethod{ID: *id456Method1})

		docs, err := resolver.ResolveControllers(docB)
		assert.NoError(t, err)
		assert.Len(t, docs, 2)
		assert.Equal(t, []did.Document{docB, docA}, docs,
			"expected docA and docB to be resolved as controller of docB")
	})

	t.Run("docA, docB and docC are controllers of docA, docB is deactivated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := types.NewMockStore(ctrl)

		resolver := Resolver{Store: store}
		// Doc B is deactivated
		docBID, _ := did.ParseDID("did:nuts:B")
		docB := did.Document{ID: *docBID}
		store.EXPECT().Resolve(docB.ID, gomock.Any()).Return(&docB, &types.DocumentMetadata{}, nil)

		// Doc C is active
		docCID, _ := did.ParseDID("did:nuts:C")
		docCIDCapInv := *docCID
		docCIDCapInv.Fragment = "cap-inv"
		docC := did.Document{ID: *docCID}
		docC.AddCapabilityInvocation(&did.VerificationMethod{ID: docCIDCapInv})
		store.EXPECT().Resolve(docC.ID, gomock.Any()).Return(&docC, &types.DocumentMetadata{}, nil)

		// Doc A is active
		docAID, _ := did.ParseDID("did:nuts:A")
		docAIDCapInv := *docAID
		docAIDCapInv.Fragment = "cap-inv"
		docA := did.Document{ID: *docAID}
		docA.Controller = []did.DID{docA.ID, docB.ID, docC.ID}
		docA.AddCapabilityInvocation(&did.VerificationMethod{ID: docAIDCapInv})

		docs, err := resolver.ResolveControllers(docA)
		assert.NoError(t, err)
		assert.Len(t, docs, 2)
		assert.Contains(t, docs, docA, "expected docA to be resolved as controller of docA")
		assert.Contains(t, docs, docC, "expected docC to be resolved as controller of docA")
	})

	t.Run("docA is controller of docB, docA has explicit self link in Controllers", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := types.NewMockStore(ctrl)

		resolver := Resolver{Store: store}
		docA := did.Document{ID: *id123, Controller: []did.DID{*id123}}
		docA.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})

		store.EXPECT().Resolve(*id123, gomock.Any()).Return(&docA, &types.DocumentMetadata{}, nil)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}

		docs, err := resolver.ResolveControllers(docB)
		assert.NoError(t, err)
		assert.Len(t, docs, 1)
		assert.Equal(t, docA, docs[0],
			"expected docA to be resolved as controller for docB")
	})

	t.Run("error - Resolve can not find the document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := types.NewMockStore(ctrl)

		resolver := Resolver{Store: store}
		store.EXPECT().Resolve(*id123, gomock.Any()).Return(nil, nil, types.ErrNotFound)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}

		docs, err := resolver.ResolveControllers(docB)
		assert.EqualError(t, err, "unable to resolve controllers: unable to find the DID document")
		assert.Len(t, docs, 0)
	})
}

func TestKeyResolver_ResolvePublicKey(t *testing.T) {
	didStore := store.NewMemoryStore()
	keyResolver := KeyResolver{Store: didStore}
	keyCreator := &mockKeyCreator{t: t, jwkStr: jwkString}
	docCreator := Creator{KeyStore: keyCreator}
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
