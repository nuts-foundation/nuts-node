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

package didnuts

import (
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
	"time"
)

func TestNutsDIDResolver_Resolve(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")
	id456, _ := did.ParseDID("did:nuts:456")
	docA := did.Document{ID: *id123}
	docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}
	resolveTime := time.Date(2010, 1, 1, 1, 1, 1, 0, time.UTC)
	resolveMD := &resolver.ResolveMetadata{ResolveTime: &resolveTime}

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		didStore := didstore.NewMockStore(ctrl)
		nutsResolver := Resolver{Store: didStore}
		doc := did.Document{ID: *id123}
		id123Method1, _ := did.ParseDIDURL("did:nuts:123#method-1")
		doc.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})
		didStore.EXPECT().Resolve(*id123, resolveMD).Return(&doc, &resolver.DocumentMetadata{}, nil)

		resultDoc, _, err := nutsResolver.Resolve(*id123, resolveMD)

		require.NoError(t, err)

		assert.Equal(t, doc.ID, resultDoc.ID)
	})

	t.Run("docA is controller of docB and docA is deactivated", func(t *testing.T) {
		t.Run("err - with resolver metadata", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			didStore := didstore.NewMockStore(ctrl)
			nutsResolver := Resolver{Store: didStore}
			didStore.EXPECT().Resolve(*id456, resolveMD).Return(&docB, &resolver.DocumentMetadata{}, nil)
			didStore.EXPECT().Resolve(*id123, resolveMD).Return(&docA, &resolver.DocumentMetadata{}, nil)

			doc, _, err := nutsResolver.Resolve(*id456, resolveMD)

			assert.Error(t, err)
			assert.Equal(t, resolver.ErrNoActiveController, err)
			assert.Nil(t, doc)
		})

		t.Run("err - without resolve metadata", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			didStore := didstore.NewMockStore(ctrl)
			nutsResolver := Resolver{Store: didStore}
			didStore.EXPECT().Resolve(*id456, nil).Return(&docB, &resolver.DocumentMetadata{}, nil)
			didStore.EXPECT().Resolve(*id123, nil).Return(&docA, &resolver.DocumentMetadata{}, nil)

			doc, _, err := nutsResolver.Resolve(*id456, nil)

			assert.Error(t, err)
			assert.Equal(t, resolver.ErrNoActiveController, err)
			assert.Nil(t, doc)
		})

		t.Run("ok - allowed deactivated", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			didStore := didstore.NewMockStore(ctrl)
			nutsResolver := Resolver{Store: didStore}
			resolveMD := &resolver.ResolveMetadata{ResolveTime: &resolveTime, AllowDeactivated: true}

			didStore.EXPECT().Resolve(*id456, resolveMD).Return(&docB, &resolver.DocumentMetadata{}, nil)

			doc, _, err := nutsResolver.Resolve(*id456, resolveMD)
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
		didStore := didstore.NewMockStore(ctrl)
		nutsResolver := Resolver{Store: didStore}
		for i := 0; i < depth; i++ {
			id, _ := did.ParseDID(fmt.Sprintf("did:nuts:%d", i))
			d := did.Document{ID: *id, Controller: []did.DID{*prevID}}
			didStore.EXPECT().Resolve(*prevID, resolveMD).Return(&prevDoc, &resolver.DocumentMetadata{}, nil).AnyTimes()
			dids[i] = id
			docs[i] = d
			prevID = id
			prevDoc = d
		}
		didStore.EXPECT().Resolve(*dids[depth-1], resolveMD).Return(&docs[depth-1], &resolver.DocumentMetadata{}, nil)

		_, _, err := nutsResolver.Resolve(*dids[depth-1], resolveMD)

		assert.Error(t, err)
		assert.Equal(t, ErrNestedDocumentsTooDeep, err)
	})
}
func TestResolveControllers(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")
	id123Method1, _ := did.ParseDIDURL("did:nuts:123#method-1")
	id456, _ := did.ParseDID("did:nuts:456")
	id456Method1, _ := did.ParseDIDURL("did:nuts:456#method-1")
	t.Run("emtpy input", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := resolver.NewMockDIDResolver(ctrl)
		docs, err := ResolveControllers(resolver, did.Document{}, nil)
		assert.NoError(t, err)
		assert.Len(t, docs, 0,
			"expected an empty list")
	})

	t.Run("doc is its own controller", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := resolver.NewMockDIDResolver(ctrl)
		doc := did.Document{ID: *id123}
		doc.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})
		docs, err := ResolveControllers(resolver, doc, nil)
		assert.NoError(t, err)
		assert.Len(t, docs, 1,
			"expected the document")
		assert.Equal(t, doc, docs[0])
	})

	t.Run("doc is deactivated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := resolver.NewMockDIDResolver(ctrl)
		doc := did.Document{ID: *id123}
		docs, err := ResolveControllers(resolver, doc, nil)
		assert.NoError(t, err)
		assert.Len(t, docs, 0,
			"expected an empty list when the document is deactivated")
	})

	t.Run("docA is controller of docB", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		nutsResolver := resolver.NewMockDIDResolver(ctrl)

		docA := did.Document{ID: *id123}
		docA.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})

		resolveTime := time.Date(2010, 1, 1, 1, 1, 1, 0, time.UTC)
		resolveMD := &resolver.ResolveMetadata{ResolveTime: &resolveTime}
		nutsResolver.EXPECT().Resolve(*id123, resolveMD).Return(&docA, &resolver.DocumentMetadata{}, nil)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}

		docs, err := ResolveControllers(nutsResolver, docB, resolveMD)
		assert.NoError(t, err)
		assert.Len(t, docs, 1)
		assert.Equal(t, docA, docs[0],
			"expected docA to be resolved as controller for docB")
	})

	t.Run("docA is controller of docB and docA is deactivated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		nutsResolver := resolver.NewMockDIDResolver(ctrl)
		docA := did.Document{ID: *id123}

		resolveTime := time.Date(2010, 1, 1, 1, 1, 1, 0, time.UTC)
		resolveMD := &resolver.ResolveMetadata{ResolveTime: &resolveTime}
		nutsResolver.EXPECT().Resolve(*id123, resolveMD).Return(&docA, &resolver.DocumentMetadata{}, nil)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}

		docs, err := ResolveControllers(nutsResolver, docB, resolveMD)
		assert.NoError(t, err)
		assert.Len(t, docs, 0)
	})

	t.Run("docA and docB are both the controllers of docB", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		nutsResolver := resolver.NewMockDIDResolver(ctrl)
		docA := did.Document{ID: *id123}
		docA.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})

		nutsResolver.EXPECT().Resolve(*id123, gomock.Any()).Return(&docA, &resolver.DocumentMetadata{}, nil)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123, *id456}}
		docB.AddCapabilityInvocation(&did.VerificationMethod{ID: *id456Method1})

		docs, err := ResolveControllers(nutsResolver, docB, nil)
		assert.NoError(t, err)
		assert.Len(t, docs, 2)
		assert.Equal(t, []did.Document{docB, docA}, docs,
			"expected docA and docB to be resolved as controller of docB")
	})

	t.Run("docA and docB are both the controllers of docB, resolve by source transaction", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		nutsResolver := resolver.NewMockDIDResolver(ctrl)
		docA := did.Document{ID: *id123}
		docA.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})

		// when we resolve by source TX, we will not find the other controller
		nutsResolver.EXPECT().Resolve(*id123, gomock.Any()).Return(nil, nil, resolver.ErrNotFound)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123, *id456}}
		docB.AddCapabilityInvocation(&did.VerificationMethod{ID: *id456Method1})

		docs, err := ResolveControllers(nutsResolver, docB, nil)
		assert.NoError(t, err)
		assert.Len(t, docs, 1)
		assert.Equal(t, []did.Document{docB}, docs,
			"expected docB to be resolved as controller of docB")
	})

	t.Run("docA, docB and docC are controllers of docA, docB is deactivated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		nutsResolver := resolver.NewMockDIDResolver(ctrl)
		// Doc B is deactivated
		docBID, _ := did.ParseDID("did:nuts:B")
		docB := did.Document{ID: *docBID}
		nutsResolver.EXPECT().Resolve(docB.ID, gomock.Any()).Return(&docB, &resolver.DocumentMetadata{}, nil)

		// Doc C is active
		docCID, _ := did.ParseDID("did:nuts:C")
		docCIDCapInv := *docCID
		docCIDCapInv.Fragment = "cap-inv"
		docC := did.Document{ID: *docCID}
		docC.AddCapabilityInvocation(&did.VerificationMethod{ID: docCIDCapInv})
		nutsResolver.EXPECT().Resolve(docC.ID, gomock.Any()).Return(&docC, &resolver.DocumentMetadata{}, nil)

		// Doc A is active
		docAID, _ := did.ParseDID("did:nuts:A")
		docAIDCapInv := *docAID
		docAIDCapInv.Fragment = "cap-inv"
		docA := did.Document{ID: *docAID}
		docA.Controller = []did.DID{docA.ID, docB.ID, docC.ID}
		docA.AddCapabilityInvocation(&did.VerificationMethod{ID: docAIDCapInv})

		docs, err := ResolveControllers(nutsResolver, docA, nil)
		assert.NoError(t, err)
		assert.Len(t, docs, 2)
		assert.Contains(t, docs, docA, "expected docA to be resolved as controller of docA")
		assert.Contains(t, docs, docC, "expected docC to be resolved as controller of docA")
	})

	t.Run("docA is controller of docB, docA has explicit self link in Controllers", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		nutsResolver := resolver.NewMockDIDResolver(ctrl)
		docA := did.Document{ID: *id123, Controller: []did.DID{*id123}}
		docA.AddCapabilityInvocation(&did.VerificationMethod{ID: *id123Method1})

		nutsResolver.EXPECT().Resolve(*id123, gomock.Any()).Return(&docA, &resolver.DocumentMetadata{}, nil)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}

		docs, err := ResolveControllers(nutsResolver, docB, nil)
		assert.NoError(t, err)
		assert.Len(t, docs, 1)
		assert.Equal(t, docA, docs[0],
			"expected docA to be resolved as controller for docB")
	})

	t.Run("ok - Resolve can not find the document", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		nutsResolver := resolver.NewMockDIDResolver(ctrl)
		nutsResolver.EXPECT().Resolve(*id123, gomock.Any()).Return(nil, nil, resolver.ErrNotFound)

		docB := did.Document{ID: *id456, Controller: []did.DID{*id123}}

		docs, err := ResolveControllers(nutsResolver, docB, nil)
		require.NoError(t, err)
		assert.Len(t, docs, 0)
	})
}
