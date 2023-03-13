/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package v1

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/audit"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapper_Preprocess(t *testing.T) {
	w := &Wrapper{}
	echoCtx := echo.New().NewContext(&http.Request{}, nil)
	echoCtx.Set(core.UserContextKey, "user")

	w.Preprocess("foo", echoCtx)

	audit.AssertAuditInfo(t, echoCtx, "user@", "VDR", "foo")
	assert.Equal(t, "foo", echoCtx.Get(core.OperationIDContextKey))
	assert.Equal(t, "VDR", echoCtx.Get(core.ModuleNameContextKey))
	assert.Same(t, w, echoCtx.Get(core.StatusCodeResolverContextKey))
}

func TestWrapper_CreateDID(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:1")
	didDoc := &did.Document{
		ID: *id,
	}

	t.Run("ok - defaults", func(t *testing.T) {
		ctx := newMockContext(t)

		var didDocReturn did.Document
		didCreateRequest := DIDCreateRequest{}
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDCreateRequest)
			*p = didCreateRequest
			return nil
		})
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			didDocReturn = f2.(did.Document)
			return nil
		})
		ctx.vdr.EXPECT().Create(gomock.Any(), gomock.Any()).Return(didDoc, nil, nil)
		err := ctx.client.CreateDID(ctx.echo)

		require.NoError(t, err)
		assert.Equal(t, *id, didDocReturn.ID)
	})

	t.Run("ok - non defaults", func(t *testing.T) {
		ctx := newMockContext(t)

		var didDocReturn did.Document
		controllers := []string{"did:nuts:2"}
		truep := func() *bool { t := true; return &t }
		didCreateRequest := DIDCreateRequest{
			VerificationMethodRelationship: VerificationMethodRelationship{
				AssertionMethod:      new(bool),
				Authentication:       truep(),
				CapabilityDelegation: truep(),
				CapabilityInvocation: new(bool),
				KeyAgreement:         truep(),
			},
			SelfControl: new(bool),
			Controllers: &controllers,
		}
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDCreateRequest)
			*p = didCreateRequest
			return nil
		})
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			didDocReturn = f2.(did.Document)
			return nil
		})
		ctx.vdr.EXPECT().Create(gomock.Any(), gomock.Any()).Return(didDoc, nil, nil)
		err := ctx.client.CreateDID(ctx.echo)

		require.NoError(t, err)
		assert.Equal(t, *id, didDocReturn.ID)
	})

	t.Run("error - invalid controller DID", func(t *testing.T) {
		ctx := newMockContext(t)

		controllers := []string{"not_a_did"}
		didCreateRequest := DIDCreateRequest{
			Controllers: &controllers,
		}
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDCreateRequest)
			*p = didCreateRequest
			return nil
		})
		err := ctx.client.CreateDID(ctx.echo)

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.client.ResolveStatusCode(err))
	})

	t.Run("error - create fails", func(t *testing.T) {
		ctx := newMockContext(t)

		didCreateRequest := DIDCreateRequest{}
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDCreateRequest)
			*p = didCreateRequest
			return nil
		})
		ctx.vdr.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, nil, errors.New("b00m!"))
		err := ctx.client.CreateDID(ctx.echo)

		assert.Error(t, err)
	})

	t.Run("error - bind fails", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))
		err := ctx.client.CreateDID(ctx.echo)

		assert.EqualError(t, err, "b00m!")
	})
}

func TestWrapper_GetDID(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:1")
	didDoc := &did.Document{
		ID: *id,
	}
	meta := &types.DocumentMetadata{}
	versionId := "e6efa34322812bd5ddec7f1aa3389957a2c35d19949913287407cb1068e16eb9"
	versionTime := "2021-11-03T08:25:13Z"

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)

		didResolutionResult := DIDResolutionResult{}
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			didResolutionResult = f2.(DIDResolutionResult)
			return nil
		})

		ctx.docResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(didDoc, meta, nil)
		err := ctx.client.GetDID(ctx.echo, id.String(), GetDIDParams{})

		require.NoError(t, err)
		assert.Equal(t, *id, didResolutionResult.Document.ID)
	})

	t.Run("ok - with versionId", func(t *testing.T) {
		ctx := newMockContext(t)

		didResolutionResult := DIDResolutionResult{}
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			didResolutionResult = f2.(DIDResolutionResult)
			return nil
		})

		expectedVersionHash, err := hash.ParseHex(versionId)
		require.NoError(t, err)
		ctx.docResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true, Hash: &expectedVersionHash}).Return(didDoc, meta, nil)
		err = ctx.client.GetDID(ctx.echo, id.String(), GetDIDParams{VersionId: &versionId})
		require.NoError(t, err)
		assert.Equal(t, *id, didResolutionResult.Document.ID)
	})

	t.Run("ok - with versionTime", func(t *testing.T) {
		ctx := newMockContext(t)

		didResolutionResult := DIDResolutionResult{}
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			didResolutionResult = f2.(DIDResolutionResult)
			return nil
		})

		expectedTime, err := time.Parse(time.RFC3339, versionTime)
		require.NoError(t, err)

		ctx.docResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true, ResolveTime: &expectedTime}).Return(didDoc, meta, nil)
		err = ctx.client.GetDID(ctx.echo, id.String(), GetDIDParams{VersionTime: &versionTime})
		require.NoError(t, err)
		assert.Equal(t, *id, didResolutionResult.Document.ID)
	})

	t.Run("error - wrong did format", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.client.GetDID(ctx.echo, "not a did", GetDIDParams{})

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.client.ResolveStatusCode(err))
	})

	t.Run("error - wrong versionId format", func(t *testing.T) {
		ctx := newMockContext(t)

		invalidVersionId := "123"
		err := ctx.client.GetDID(ctx.echo, id.String(), GetDIDParams{VersionId: &invalidVersionId})

		assert.ErrorIs(t, err, core.Error(http.StatusBadRequest, ""))
		assert.Equal(t, "given hash is not valid: encoding/hex: odd length hex string", err.Error())
	})

	t.Run("error - wrong versionTime format", func(t *testing.T) {
		ctx := newMockContext(t)

		invalidVersionTime := "not a time"
		err := ctx.client.GetDID(ctx.echo, id.String(), GetDIDParams{VersionTime: &invalidVersionTime})
		assert.ErrorIs(t, err, core.Error(http.StatusBadRequest, ""))
		assert.Equal(t, "versionTime has invalid format: parsing time \"not a time\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"not a time\" as \"2006\"", err.Error())
	})

	t.Run("error - versionId and versionTime are mutually exclusive", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.client.GetDID(ctx.echo, id.String(), GetDIDParams{
			VersionId:   &versionId,
			VersionTime: &versionTime,
		})

		assert.ErrorIs(t, err, core.Error(http.StatusBadRequest, ""))
		assert.Equal(t, "versionId and versionTime are mutually exclusive", err.Error())
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.docResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(nil, nil, types.ErrNotFound)
		err := ctx.client.GetDID(ctx.echo, id.String(), GetDIDParams{})

		assert.ErrorIs(t, err, types.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, ctx.client.ResolveStatusCode(err))
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.docResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(nil, nil, errors.New("b00m!"))
		err := ctx.client.GetDID(ctx.echo, id.String(), GetDIDParams{})

		assert.Error(t, err)
	})
}

func TestWrapper_ConflictedDIDs(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:1")
	didDoc := &did.Document{
		ID: *id,
	}
	meta := &types.DocumentMetadata{}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)

		var didResolutionResult []DIDResolutionResult
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			didResolutionResult = f2.([]DIDResolutionResult)
			return nil
		})

		ctx.vdr.EXPECT().ConflictedDocuments().Return([]did.Document{*didDoc}, []types.DocumentMetadata{*meta}, nil)
		err := ctx.client.ConflictedDIDs(ctx.echo)

		require.NoError(t, err)
		assert.Equal(t, *id, didResolutionResult[0].Document.ID)
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.vdr.EXPECT().ConflictedDocuments().Return(nil, nil, errors.New("b00m!"))
		err := ctx.client.ConflictedDIDs(ctx.echo)

		assert.Error(t, err)
	})
}

func TestWrapper_UpdateDID(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:1")
	didDoc := &did.Document{
		ID: *id,
	}
	didUpdate := DIDUpdateRequest{
		Document:    *didDoc,
		CurrentHash: "452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620",
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)

		var didReturn did.Document
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDUpdateRequest)
			*p = didUpdate
			return nil
		})
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			didReturn = f2.(did.Document)
			return nil
		})
		ctx.vdr.EXPECT().Update(gomock.Any(), *id, gomock.Any()).Return(nil)
		err := ctx.client.UpdateDID(ctx.echo, id.String())

		require.NoError(t, err)
		assert.Equal(t, *id, didReturn.ID)
	})

	t.Run("error - wrong did format", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.client.UpdateDID(ctx.echo, "not a did")

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.client.ResolveStatusCode(err))
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDUpdateRequest)
			*p = didUpdate
			return nil
		})
		ctx.vdr.EXPECT().Update(gomock.Any(), *id, gomock.Any()).Return(types.ErrNotFound)
		err := ctx.client.UpdateDID(ctx.echo, id.String())

		assert.ErrorIs(t, err, types.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, ctx.client.ResolveStatusCode(err))
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDUpdateRequest)
			*p = didUpdate
			return nil
		})
		ctx.vdr.EXPECT().Update(gomock.Any(), *id, gomock.Any()).Return(errors.New("b00m!"))
		err := ctx.client.UpdateDID(ctx.echo, id.String())

		assert.EqualError(t, err, "b00m!")
	})

	t.Run("error - bind goes wrong", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))
		err := ctx.client.UpdateDID(ctx.echo, id.String())

		assert.EqualError(t, err, "b00m!")
	})

	t.Run("error - document deactivated", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDUpdateRequest)
			*p = didUpdate
			return nil
		})

		ctx.vdr.EXPECT().Update(gomock.Any(), *id, gomock.Any()).Return(types.ErrDeactivated)

		err := ctx.client.UpdateDID(ctx.echo, id.String())

		assert.ErrorIs(t, err, types.ErrDeactivated)
		assert.Equal(t, http.StatusConflict, ctx.client.ResolveStatusCode(err))
	})

	t.Run("error - did not managed by this node", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDUpdateRequest)
			*p = didUpdate
			return nil
		})

		ctx.vdr.EXPECT().Update(gomock.Any(), *id, gomock.Any()).Return(types.ErrDIDNotManagedByThisNode)

		err := ctx.client.UpdateDID(ctx.echo, id.String())

		assert.ErrorIs(t, err, types.ErrDIDNotManagedByThisNode)
		assert.Equal(t, http.StatusForbidden, ctx.client.ResolveStatusCode(err))
	})
}

func TestWrapper_DeactivateDID(t *testing.T) {
	did123, _ := did.ParseDID("did:nuts:123")
	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().Deactivate(ctx.requestCtx, *did123).Return(nil)

		ctx.echo.EXPECT().NoContent(http.StatusOK)
		err := ctx.client.DeactivateDID(ctx.echo, did123.String())
		assert.NoError(t, err)
	})

	t.Run("error - invalid DID format", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.client.DeactivateDID(ctx.echo, "invalidFormattedDID")

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.client.ResolveStatusCode(err))
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.docUpdater.EXPECT().Deactivate(ctx.requestCtx, *did123).Return(types.ErrNotFound)

		err := ctx.client.DeactivateDID(ctx.echo, did123.String())

		assert.ErrorIs(t, err, types.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, ctx.client.ResolveStatusCode(err))
	})

	t.Run("error - document already deactivated", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().Deactivate(ctx.requestCtx, *did123).Return(types.ErrDeactivated)

		err := ctx.client.DeactivateDID(ctx.echo, did123.String())

		assert.ErrorIs(t, err, types.ErrDeactivated)
		assert.Equal(t, http.StatusConflict, ctx.client.ResolveStatusCode(err))
	})

	t.Run("error - did not managed by this node", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().Deactivate(ctx.requestCtx, *did123).Return(types.ErrDIDNotManagedByThisNode)

		err := ctx.client.DeactivateDID(ctx.echo, did123.String())

		assert.ErrorIs(t, err, types.ErrDIDNotManagedByThisNode)
		assert.Equal(t, http.StatusForbidden, ctx.client.ResolveStatusCode(err))
	})
}

func TestWrapper_AddNewVerificationMethod(t *testing.T) {
	did123, _ := did.ParseDID("did:nuts:123")
	did123Method, _ := did.ParseDIDURL("did:nuts:123#abc-method-1")

	newMethod := &did.VerificationMethod{ID: *did123Method}

	t.Run("ok - without key usage", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().AddVerificationMethod(ctx.requestCtx, *did123, didservice.DefaultCreationOptions().KeyFlags).Return(newMethod, nil)

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			return nil
		})
		var createdMethodResult did.VerificationMethod
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			createdMethodResult = f2.(did.VerificationMethod)
			return nil
		})
		err := ctx.client.AddNewVerificationMethod(ctx.echo, did123.String())
		assert.NoError(t, err)
		assert.Equal(t, *newMethod, createdMethodResult)
	})

	t.Run("ok - with key usage", func(t *testing.T) {
		ctx := newMockContext(t)

		expectedKeyUsage := didservice.DefaultCreationOptions().KeyFlags | types.AuthenticationUsage | types.CapabilityDelegationUsage
		ctx.docUpdater.EXPECT().AddVerificationMethod(ctx.requestCtx, *did123, expectedKeyUsage).Return(newMethod, nil)
		trueBool := true
		requestBody := AddNewVerificationMethodJSONRequestBody{
			Authentication:       &trueBool,
			CapabilityDelegation: &trueBool,
		}
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*AddNewVerificationMethodJSONRequestBody)
			*p = requestBody
			return nil
		})
		var createdMethodResult did.VerificationMethod
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			createdMethodResult = f2.(did.VerificationMethod)
			return nil
		})
		err := ctx.client.AddNewVerificationMethod(ctx.echo, did123.String())
		assert.NoError(t, err)
		assert.Equal(t, *newMethod, createdMethodResult)
	})

	t.Run("error - invalid did", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.client.AddNewVerificationMethod(ctx.echo, "not a did")

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.client.ResolveStatusCode(err))
	})

	t.Run("error - internal error", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			return nil
		})
		ctx.docUpdater.EXPECT().AddVerificationMethod(ctx.requestCtx, gomock.Any(), gomock.Any()).Return(nil, errors.New("something went wrong"))

		err := ctx.client.AddNewVerificationMethod(ctx.echo, did123.String())

		assert.EqualError(t, err, "something went wrong")
	})
}

func TestWrapper_DeleteVerificationMethod(t *testing.T) {
	did123, _ := did.ParseDID("did:nuts:123")
	did123Method, _ := did.ParseDIDURL("did:nuts:123#abc-method-1")

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().RemoveVerificationMethod(ctx.requestCtx, *did123, *did123Method).Return(nil)
		ctx.echo.EXPECT().NoContent(http.StatusNoContent)

		err := ctx.client.DeleteVerificationMethod(ctx.echo, did123.String(), did123Method.String())
		assert.NoError(t, err)
	})

	t.Run("error - invalid did", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.client.DeleteVerificationMethod(ctx.echo, "invalid did", did123Method.String())

		assert.ErrorIs(t, err, did.ErrInvalidDID)
	})

	t.Run("error - invalid kid", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.client.DeleteVerificationMethod(ctx.echo, did123.String(), "invalid kid")

		assert.EqualError(t, err, "given kid could not be parsed: invalid DID: input does not begin with 'did:' prefix")
	})

	t.Run("error - internal error", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().RemoveVerificationMethod(ctx.requestCtx, *did123, *did123Method).Return(errors.New("something went wrong"))

		err := ctx.client.DeleteVerificationMethod(ctx.echo, did123.String(), did123Method.String())

		assert.EqualError(t, err, "could not remove verification method from document: something went wrong")
	})
}

func Test_ErrorStatusCodes(t *testing.T) {
	assert.NotNil(t, (&Wrapper{}).ResolveStatusCode(nil))
}

type mockContext struct {
	ctrl        *gomock.Controller
	echo        *mock.MockContext
	vdr         *types.MockVDR
	docResolver *types.MockDocResolver
	docUpdater  *types.MockDocManipulator
	client      *Wrapper
	requestCtx  context.Context
}

func newMockContext(t *testing.T) mockContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	vdr := types.NewMockVDR(ctrl)
	docManipulator := types.NewMockDocManipulator(ctrl)
	docResolver := types.NewMockDocResolver(ctrl)
	client := &Wrapper{VDR: vdr, DocManipulator: docManipulator, DocResolver: docResolver}
	requestCtx := audit.TestContext()
	echoMock := mock.NewMockContext(ctrl)
	request, _ := http.NewRequestWithContext(requestCtx, http.MethodGet, "/", nil)
	echoMock.EXPECT().Request().Return(request).AnyTimes()

	return mockContext{
		ctrl:        ctrl,
		echo:        echoMock,
		vdr:         vdr,
		client:      client,
		docResolver: docResolver,
		docUpdater:  docManipulator,
		requestCtx:  requestCtx,
	}
}
