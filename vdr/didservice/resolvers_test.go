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
	"errors"
	"fmt"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestResolver_Resolve(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")
	id456, _ := did.ParseDID("did:nuts:456")
	docA := did.Document{ID: *id123}
	docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}
	resolveTime := time.Date(2010, 1, 1, 1, 1, 1, 0, time.UTC)
	resolveMD := &types.ResolveMetadata{ResolveTime: &resolveTime}

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := didstore.NewMockStore(ctrl)
		resolver := Resolver{Store: store}
		doc := did.Document{ID: *id123}
		id123Method1, _ := did.ParseDIDURL("did:nuts:123#method-1")
		doc.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})
		store.EXPECT().Resolve(*id123, resolveMD).Return(&doc, &types.DocumentMetadata{}, nil)

		resultDoc, _, err := resolver.Resolve(*id123, resolveMD)

		require.NoError(t, err)

		assert.Equal(t, doc.ID, resultDoc.ID)
	})

	t.Run("docA is controller of docB and docA is deactivated", func(t *testing.T) {
		t.Run("err - with resolver metadata", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := didstore.NewMockStore(ctrl)
			resolver := Resolver{Store: store}
			store.EXPECT().Resolve(*id456, resolveMD).Return(&docB, &types.DocumentMetadata{}, nil)
			store.EXPECT().Resolve(*id123, resolveMD).Return(&docA, &types.DocumentMetadata{}, nil)

			doc, _, err := resolver.Resolve(*id456, resolveMD)

			assert.Error(t, err)
			assert.Equal(t, types.ErrNoActiveController, err)
			assert.Nil(t, doc)
		})

		t.Run("err - without resolve metadata", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := didstore.NewMockStore(ctrl)
			resolver := Resolver{Store: store}
			store.EXPECT().Resolve(*id456, nil).Return(&docB, &types.DocumentMetadata{}, nil)
			store.EXPECT().Resolve(*id123, nil).Return(&docA, &types.DocumentMetadata{}, nil)

			doc, _, err := resolver.Resolve(*id456, nil)

			assert.Error(t, err)
			assert.Equal(t, types.ErrNoActiveController, err)
			assert.Nil(t, doc)
		})

		t.Run("ok - allowed deactivated", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := didstore.NewMockStore(ctrl)
			resolver := Resolver{Store: store}
			resolveMD := &types.ResolveMetadata{ResolveTime: &resolveTime, AllowDeactivated: true}

			store.EXPECT().Resolve(*id456, resolveMD).Return(&docB, &types.DocumentMetadata{}, nil)

			doc, _, err := resolver.Resolve(*id456, resolveMD)
			assert.NoError(t, err)
			assert.Equal(t, docB, *doc)
		})
	})

	t.Run("Controller hierarchy nested too deeply", func(t *testing.T) {
		depth := maxControllerDepth
		ctrl := gomock.NewController(t)
		rootID, _ := did.ParseDID("did:nuts:root")
		rootDoc := did.Document{ID: *rootID}
		dids := make([]*did.DID, depth)
		docs := make([]did.Document, depth)
		prevID := rootID
		prevDoc := rootDoc
		store := didstore.NewMockStore(ctrl)
		resolver := Resolver{Store: store}
		for i := 0; i < depth; i++ {
			id, _ := did.ParseDID(fmt.Sprintf("did:nuts:%d", i))
			d := did.Document{ID: *id, Controller: []did.DID{*prevID}}
			store.EXPECT().Resolve(*prevID, resolveMD).Return(&prevDoc, &types.DocumentMetadata{}, nil).AnyTimes()
			dids[i] = id
			docs[i] = d
			prevID = id
			prevDoc = d
		}
		store.EXPECT().Resolve(*dids[depth-1], resolveMD).Return(&docs[depth-1], &types.DocumentMetadata{}, nil)

		_, _, err := resolver.Resolve(*dids[depth-1], resolveMD)

		assert.Error(t, err)
		assert.Equal(t, ErrNestedDocumentsTooDeep, err)
	})
}

func TestResolver_ResolveControllers(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")
	id123Method1, _ := did.ParseDIDURL("did:nuts:123#method-1")
	id456, _ := did.ParseDID("did:nuts:456")
	id456Method1, _ := did.ParseDIDURL("did:nuts:456#method-1")
	t.Run("emtpy input", func(t *testing.T) {
		resolver := Resolver{}
		docs, err := resolver.ResolveControllers(did.Document{}, nil)
		assert.NoError(t, err)
		assert.Len(t, docs, 0,
			"expected an empty list")
	})

	t.Run("doc is its own controller", func(t *testing.T) {
		resolver := Resolver{}
		doc := did.Document{ID: *id123}
		doc.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})
		docs, err := resolver.ResolveControllers(doc, nil)
		assert.NoError(t, err)
		assert.Len(t, docs, 1,
			"expected the document")
		assert.Equal(t, doc, docs[0])
	})

	t.Run("doc is deactivated", func(t *testing.T) {
		resolver := Resolver{}
		doc := did.Document{ID: *id123}
		docs, err := resolver.ResolveControllers(doc, nil)
		assert.NoError(t, err)
		assert.Len(t, docs, 0,
			"expected an empty list when the document is deactivated")
	})

	t.Run("docA is controller of docB", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		store := didstore.NewMockStore(ctrl)

		resolver := Resolver{Store: store}
		docA := did.Document{ID: *id123}
		docA.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})

		resolveTime := time.Date(2010, 1, 1, 1, 1, 1, 0, time.UTC)
		resolveMD := &types.ResolveMetadata{ResolveTime: &resolveTime}
		store.EXPECT().Resolve(*id123, resolveMD).Return(&docA, &types.DocumentMetadata{}, nil)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}

		docs, err := resolver.ResolveControllers(docB, resolveMD)
		assert.NoError(t, err)
		assert.Len(t, docs, 1)
		assert.Equal(t, docA, docs[0],
			"expected docA to be resolved as controller for docB")
	})

	t.Run("docA is controller of docB and docA is deactivated", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		store := didstore.NewMockStore(ctrl)

		resolver := Resolver{Store: store}
		docA := did.Document{ID: *id123}

		resolveTime := time.Date(2010, 1, 1, 1, 1, 1, 0, time.UTC)
		resolveMD := &types.ResolveMetadata{ResolveTime: &resolveTime}
		store.EXPECT().Resolve(*id123, resolveMD).Return(&docA, &types.DocumentMetadata{}, nil)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}

		docs, err := resolver.ResolveControllers(docB, resolveMD)
		assert.NoError(t, err)
		assert.Len(t, docs, 0)
	})

	t.Run("docA and docB are both the controllers of docB", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		store := didstore.NewMockStore(ctrl)

		resolver := Resolver{Store: store}
		docA := did.Document{ID: *id123}
		docA.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})

		store.EXPECT().Resolve(*id123, gomock.Any()).Return(&docA, &types.DocumentMetadata{}, nil)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123, *id456}}
		docB.AddCapabilityInvocation(&did.VerificationMethod{ID: *id456Method1})

		docs, err := resolver.ResolveControllers(docB, nil)
		assert.NoError(t, err)
		assert.Len(t, docs, 2)
		assert.Equal(t, []did.Document{docB, docA}, docs,
			"expected docA and docB to be resolved as controller of docB")
	})

	t.Run("docA, docB and docC are controllers of docA, docB is deactivated", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		store := didstore.NewMockStore(ctrl)

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

		docs, err := resolver.ResolveControllers(docA, nil)
		assert.NoError(t, err)
		assert.Len(t, docs, 2)
		assert.Contains(t, docs, docA, "expected docA to be resolved as controller of docA")
		assert.Contains(t, docs, docC, "expected docC to be resolved as controller of docA")
	})

	t.Run("docA is controller of docB, docA has explicit self link in Controllers", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		store := didstore.NewMockStore(ctrl)

		resolver := Resolver{Store: store}
		docA := did.Document{ID: *id123, Controller: []did.DID{*id123}}
		docA.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})

		store.EXPECT().Resolve(*id123, gomock.Any()).Return(&docA, &types.DocumentMetadata{}, nil)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}

		docs, err := resolver.ResolveControllers(docB, nil)
		assert.NoError(t, err)
		assert.Len(t, docs, 1)
		assert.Equal(t, docA, docs[0],
			"expected docA to be resolved as controller for docB")
	})

	t.Run("error - Resolve can not find the document", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		store := didstore.NewMockStore(ctrl)

		resolver := Resolver{Store: store}
		store.EXPECT().Resolve(*id123, gomock.Any()).Return(nil, nil, types.ErrNotFound)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}

		docs, err := resolver.ResolveControllers(docB, nil)
		assert.EqualError(t, err, "unable to resolve controller ref: unable to find the DID document")
		assert.Len(t, docs, 0)
	})
}

func TestNutsKeyResolver_ResolvePublicKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	docResolver := types.NewMockDocResolver(ctrl)
	keyResolver := NutsKeyResolver{Resolver: docResolver}
	keyCreator := newMockKeyCreator()
	docCreator := Creator{KeyStore: keyCreator}
	doc, _, _ := docCreator.Create(nil, DefaultCreationOptions())

	t.Run("ok by hash", func(t *testing.T) {
		docResolver.EXPECT().Resolve(testDID, gomock.Any()).Do(func(arg0 interface{}, arg1 interface{}) {
			resolveMetadata := arg1.(*types.ResolveMetadata)
			assert.Equal(t, hash.EmptyHash(), *resolveMetadata.SourceTransaction)
		}).Return(doc, nil, nil)

		key, err := keyResolver.ResolvePublicKey(mockKID, []hash.SHA256Hash{hash.EmptyHash()})
		require.NoError(t, err)

		assert.NotNil(t, key)
	})

}

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
		store := didstore.NewMockStore(ctrl)

		store.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)

		actual, err := ServiceResolver{Store: store}.Resolve(MakeServiceReference(*didB, "simple"), DefaultMaxServiceReferenceDepth)

		assert.NoError(t, err)
		assert.Equal(t, docB.Service[0], actual)
	})
	t.Run("ok - external", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := didstore.NewMockStore(ctrl)

		store.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)
		store.EXPECT().Resolve(*didA, nil).MinTimes(1).Return(&docA, meta, nil)

		actual, err := ServiceResolver{Store: store}.Resolve(MakeServiceReference(*didB, "external"), DefaultMaxServiceReferenceDepth)

		assert.NoError(t, err)
		assert.Equal(t, docA.Service[0], actual)
	})
	t.Run("error - cyclic reference (yields refs too deep)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := didstore.NewMockStore(ctrl)

		store.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)

		actual, err := ServiceResolver{Store: store}.Resolve(MakeServiceReference(*didB, "cyclic-ref"), DefaultMaxServiceReferenceDepth)

		assert.EqualError(t, err, "service references are nested to deeply before resolving to a non-reference")
		assert.Empty(t, actual)
	})
	t.Run("error - invalid ref", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := didstore.NewMockStore(ctrl)

		store.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)

		actual, err := ServiceResolver{Store: store}.Resolve(MakeServiceReference(*didB, "invalid-ref"), DefaultMaxServiceReferenceDepth)

		assert.EqualError(t, err, "DID service query invalid: endpoint URI path must be /serviceEndpoint")
		assert.Empty(t, actual)
	})
	t.Run("error - service not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := didstore.NewMockStore(ctrl)

		store.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(&docB, meta, nil)

		actual, err := ServiceResolver{Store: store}.Resolve(MakeServiceReference(*didB, "non-existent"), DefaultMaxServiceReferenceDepth)

		assert.EqualError(t, err, "service not found in DID Document")
		assert.Empty(t, actual)
	})
	t.Run("error - DID not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := didstore.NewMockStore(ctrl)

		store.EXPECT().Resolve(*didB, nil).MinTimes(1).Return(nil, nil, types.ErrNotFound)

		actual, err := ServiceResolver{Store: store}.Resolve(MakeServiceReference(*didB, "non-existent"), DefaultMaxServiceReferenceDepth)

		assert.EqualError(t, err, "unable to find the DID document")
		assert.Empty(t, actual)
	})

}

func TestKeyResolver_ResolveKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := didstore.NewMockStore(ctrl)
	keyResolver := KeyResolver{Store: store}

	keyCreator := newMockKeyCreator()
	docCreator := Creator{KeyStore: keyCreator}
	doc, _, err := docCreator.Create(nil, DefaultCreationOptions())
	require.NoError(t, err)
	store.EXPECT().Resolve(doc.ID, gomock.Any()).AnyTimes().Return(doc, nil, nil)

	t.Run("ok - it finds the key", func(t *testing.T) {
		keyId, key, err := keyResolver.ResolveKey(doc.ID, nil, types.AssertionMethod)
		require.NoError(t, err)
		assert.Equal(t, doc.VerificationMethod[0].ID.URI(), keyId)
		assert.NotNil(t, key)
	})

	t.Run("error - document not found", func(t *testing.T) {
		unknownDID := did.MustParseDID("did:example:123")
		store.EXPECT().Resolve(unknownDID, gomock.Any()).Return(nil, nil, types.ErrNotFound)
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

func TestKeyResolver_ResolveKeyByID(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := didstore.NewMockStore(ctrl)
	keyResolver := KeyResolver{Store: store}

	keyCreator := newMockKeyCreator()
	docCreator := Creator{KeyStore: keyCreator}
	doc, _, err := docCreator.Create(nil, DefaultCreationOptions())
	require.NoError(t, err)
	store.EXPECT().Resolve(doc.ID, gomock.Any()).AnyTimes().Return(doc, nil, nil)
	keyID := doc.VerificationMethod[0].ID

	t.Run("ok - it finds the key", func(t *testing.T) {
		key, err := keyResolver.ResolveKeyByID(keyID.String(), nil, types.AssertionMethod)
		assert.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("error - invalid key ID", func(t *testing.T) {
		key, err := keyResolver.ResolveKeyByID("abcdef", nil, types.AssertionMethod)
		assert.EqualError(t, err, "invalid key ID (id=abcdef): invalid DID: input length is less than 7")
		assert.Nil(t, key)
	})

	t.Run("error - document not found", func(t *testing.T) {
		unknownDID := did.MustParseDIDURL("did:example:123")
		store.EXPECT().Resolve(unknownDID, gomock.Any()).Return(nil, nil, types.ErrNotFound)
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
	assert.True(t, IsFunctionalResolveError(DIDServiceQueryError{Err: errors.New("oops")}))

	assert.False(t, IsFunctionalResolveError(errors.New("some error")))
	assert.False(t, IsFunctionalResolveError(types.ErrDuplicateService))
}
