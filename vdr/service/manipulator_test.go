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
	"context"
	"errors"
	"github.com/nuts-foundation/nuts-node/audit"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// manipulatorTestContext contains the controller and mocks needed for testing the Manipulator
type manipulatorTestContext struct {
	ctrl           *gomock.Controller
	mockUpdater    *types.MockDocUpdater
	mockResolver   *types.MockDocResolver
	mockKeyCreator *mockKeyCreator
	manipulator    *Manipulator
	audit          context.Context
}

func newManipulatorTestContext(t *testing.T) manipulatorTestContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	updater := types.NewMockDocUpdater(ctrl)
	resolver := types.NewMockDocResolver(ctrl)
	keyCreator := newMockKeyCreator()
	return manipulatorTestContext{
		ctrl:           ctrl,
		mockUpdater:    updater,
		mockResolver:   resolver,
		mockKeyCreator: keyCreator,
		manipulator:    &Manipulator{Updater: updater, KeyCreator: keyCreator, Resolver: resolver},
		audit:          audit.TestContext(),
	}
}

func TestManipulator_RemoveVerificationMethod(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")
	id123Method, _ := did.ParseDIDURL("did:nuts:123#method-1")
	doc := &did.Document{ID: *id123}
	publicKey := crypto.NewTestKey("did:nuts:123").Public()
	vm, _ := did.NewVerificationMethod(*id123Method, ssi.JsonWebKey2020, did.DID{}, publicKey)
	doc.AddCapabilityInvocation(vm)
	doc.AddCapabilityDelegation(vm)
	doc.AddAssertionMethod(vm)
	doc.AddAuthenticationMethod(vm)
	doc.AddKeyAgreement(vm)
	assert.Equal(t, vm, doc.CapabilityInvocation[0].VerificationMethod)
	assert.Equal(t, vm, doc.VerificationMethod[0])

	t.Run("ok", func(t *testing.T) {
		ctx := newManipulatorTestContext(t)
		ctx.mockResolver.EXPECT().Resolve(*id123, &types.ResolveMetadata{AllowDeactivated: true}).Return(doc, &types.DocumentMetadata{}, nil)
		ctx.mockUpdater.EXPECT().Update(ctx.audit, *id123, did.Document{ID: *id123})

		err := ctx.manipulator.RemoveVerificationMethod(ctx.audit, *id123, *id123Method)
		require.NoError(t, err)
		assert.Empty(t, doc.CapabilityInvocation)
		assert.Empty(t, doc.CapabilityDelegation)
		assert.Empty(t, doc.AssertionMethod)
		assert.Empty(t, doc.Authentication)
		assert.Empty(t, doc.KeyAgreement)
		assert.Empty(t, doc.VerificationMethod)
	})

	t.Run("ok - verificationMethod is not part of the document", func(t *testing.T) {
		ctx := newManipulatorTestContext(t)
		ctx.mockResolver.EXPECT().Resolve(*id123, &types.ResolveMetadata{AllowDeactivated: true}).Return(&did.Document{ID: *id123}, &types.DocumentMetadata{}, nil)

		err := ctx.manipulator.RemoveVerificationMethod(ctx.audit, *id123, *id123Method)

		assert.NoError(t, err)
	})

	t.Run("error - document is deactivated", func(t *testing.T) {
		ctx := newManipulatorTestContext(t)
		ctx.mockResolver.EXPECT().Resolve(*id123, &types.ResolveMetadata{AllowDeactivated: true}).Return(&did.Document{ID: *id123}, &types.DocumentMetadata{Deactivated: true}, nil)

		err := ctx.manipulator.RemoveVerificationMethod(ctx.audit, *id123, *id123Method)
		assert.EqualError(t, err, "the DID document has been deactivated")
		assert.True(t, errors.Is(err, types.ErrDeactivated))
	})
}

func TestManipulator_CreateNewAuthenticationMethodForDID(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")

	kc := newMockKeyCreator()

	t.Run("ok", func(t *testing.T) {
		// Prepare a document with an authenticationMethod:
		document := &did.Document{ID: *id123}
		method, err := CreateNewVerificationMethodForDID(audit.TestContext(), document.ID, kc)
		require.NoError(t, err)
		document.AddCapabilityInvocation(method)

		assert.NotNil(t, method)
		assert.Len(t, document.CapabilityInvocation, 1)
		assert.Equal(t, method.ID.String(), document.CapabilityInvocation[0].ID.String())
		assert.Equal(t, kc.kid, document.CapabilityInvocation[0].ID.String())
	})
}

func TestManipulator_AddKey(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDIDURL("did:nuts:123#key-1")

	t.Run("ok - add a new key", func(t *testing.T) {
		ctx := newManipulatorTestContext(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		ctx.mockResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{}, nil)
		var updatedDocument did.Document
		ctx.mockUpdater.EXPECT().Update(ctx.audit, *id, gomock.Any()).Do(func(_ context.Context, _ did.DID, doc did.Document) {
			updatedDocument = doc
		})

		key, err := ctx.manipulator.AddVerificationMethod(ctx.audit, *id, types.AuthenticationUsage)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, key.Controller, *id,
			"expected method to have DID as controller")
		assert.Len(t, updatedDocument.VerificationMethod, 2)
		assert.Len(t, updatedDocument.Authentication, 1)
		assert.Contains(t, updatedDocument.VerificationMethod, key)
		assert.Equal(t, updatedDocument.Authentication[0].VerificationMethod, key)
	})

	t.Run("error - vdr.update throws an error", func(t *testing.T) {
		ctx := newManipulatorTestContext(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		ctx.mockResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{}, nil)
		ctx.mockUpdater.EXPECT().Update(ctx.audit, *id, gomock.Any()).Return(types.ErrNotFound)

		key, err := ctx.manipulator.AddVerificationMethod(ctx.audit, *id, 0)
		assert.ErrorIs(t, err, types.ErrNotFound)
		assert.Nil(t, key)
	})

	t.Run("error - did is deactivated", func(t *testing.T) {
		ctx := newManipulatorTestContext(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		ctx.mockResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{Deactivated: true}, nil)

		key, err := ctx.manipulator.AddVerificationMethod(nil, *id, 0)

		assert.ErrorIs(t, err, types.ErrDeactivated)
		assert.Nil(t, key)
	})
}

func TestManipulator_Deactivate(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDIDURL("did:nuts:123#key-1")

	ctx := newManipulatorTestContext(t)

	currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
	currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})

	ctx.mockResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{}, nil)
	expectedDocument := CreateDocument()
	expectedDocument.ID = *id
	ctx.mockUpdater.EXPECT().Update(ctx.audit, *id, expectedDocument)

	err := ctx.manipulator.Deactivate(ctx.audit, *id)
	require.NoError(t, err)
}
