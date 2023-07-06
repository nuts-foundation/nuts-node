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
	"github.com/nuts-foundation/nuts-node/audit"
	"net/http"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestWrapper_CreateDID(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:1")
	didDoc := &did.Document{
		ID: *id,
	}

	t.Run("ok - defaults", func(t *testing.T) {
		ctx := newMockContext(t)
		request := DIDCreateRequest{}
		ctx.vdr.EXPECT().Create(gomock.Any(), gomock.Any()).Return(didDoc, nil, nil)

		response, err := ctx.client.CreateDID(nil, CreateDIDRequestObject{Body: &request})

		require.NoError(t, err)
		assert.Equal(t, *id, response.(CreateDID200JSONResponse).ID)
	})

	t.Run("ok - non defaults", func(t *testing.T) {
		ctx := newMockContext(t)
		controllers := []string{"did:nuts:2"}
		truep := func() *bool { t := true; return &t }
		request := DIDCreateRequest{
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
		ctx.vdr.EXPECT().Create(gomock.Any(), gomock.Any()).Return(didDoc, nil, nil)

		response, err := ctx.client.CreateDID(nil, CreateDIDRequestObject{Body: &request})

		require.NoError(t, err)
		assert.Equal(t, *id, response.(CreateDID200JSONResponse).ID)
	})

	t.Run("error - invalid controller DID", func(t *testing.T) {
		ctx := newMockContext(t)
		controllers := []string{"not_a_did"}
		request := DIDCreateRequest{
			Controllers: &controllers,
		}

		response, err := ctx.client.CreateDID(nil, CreateDIDRequestObject{Body: &request})

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.client.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - create fails", func(t *testing.T) {
		ctx := newMockContext(t)
		request := DIDCreateRequest{}
		ctx.vdr.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, nil, errors.New("b00m!"))

		response, err := ctx.client.CreateDID(nil, CreateDIDRequestObject{Body: &request})

		assert.Error(t, err)
		assert.Nil(t, response)
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
		ctx.docResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(didDoc, meta, nil)

		response, err := ctx.client.GetDID(nil, GetDIDRequestObject{Did: id.String()})

		require.NoError(t, err)
		assert.Equal(t, *id, response.(GetDID200JSONResponse).Document.ID)
	})

	t.Run("ok - with versionId", func(t *testing.T) {
		ctx := newMockContext(t)
		expectedVersionHash, err := hash.ParseHex(versionId)
		require.NoError(t, err)
		ctx.docResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true, Hash: &expectedVersionHash}).Return(didDoc, meta, nil)

		response, err := ctx.client.GetDID(nil, GetDIDRequestObject{Did: id.String(), Params: GetDIDParams{VersionId: &versionId}})

		require.NoError(t, err)
		assert.Equal(t, *id, response.(GetDID200JSONResponse).Document.ID)
	})

	t.Run("ok - with versionTime", func(t *testing.T) {
		ctx := newMockContext(t)
		expectedTime, err := time.Parse(time.RFC3339, versionTime)
		require.NoError(t, err)
		ctx.docResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true, ResolveTime: &expectedTime}).Return(didDoc, meta, nil)

		response, err := ctx.client.GetDID(nil, GetDIDRequestObject{Did: id.String(), Params: GetDIDParams{VersionTime: &versionTime}})

		require.NoError(t, err)
		assert.Equal(t, *id, response.(GetDID200JSONResponse).Document.ID)
	})

	t.Run("error - wrong did format", func(t *testing.T) {
		ctx := newMockContext(t)

		response, err := ctx.client.GetDID(nil, GetDIDRequestObject{Did: "not_a_did"})

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.client.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - wrong versionId format", func(t *testing.T) {
		ctx := newMockContext(t)
		invalidVersionId := "123"

		response, err := ctx.client.GetDID(nil, GetDIDRequestObject{Did: id.String(), Params: GetDIDParams{VersionId: &invalidVersionId}})

		assert.ErrorIs(t, err, core.Error(http.StatusBadRequest, ""))
		assert.Equal(t, "given hash is not valid: encoding/hex: odd length hex string", err.Error())
		assert.Nil(t, response)
	})

	t.Run("error - wrong versionTime format", func(t *testing.T) {
		ctx := newMockContext(t)
		invalidVersionTime := "not a time"

		response, err := ctx.client.GetDID(nil, GetDIDRequestObject{Did: id.String(), Params: GetDIDParams{VersionTime: &invalidVersionTime}})

		assert.ErrorIs(t, err, core.Error(http.StatusBadRequest, ""))
		assert.Equal(t, "versionTime has invalid format: parsing time \"not a time\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"not a time\" as \"2006\"", err.Error())
		assert.Nil(t, response)
	})

	t.Run("error - versionId and versionTime are mutually exclusive", func(t *testing.T) {
		ctx := newMockContext(t)

		response, err := ctx.client.GetDID(nil, GetDIDRequestObject{
			Did:    id.String(),
			Params: GetDIDParams{VersionId: &versionId, VersionTime: &versionTime},
		})

		assert.ErrorIs(t, err, core.Error(http.StatusBadRequest, ""))
		assert.Equal(t, "versionId and versionTime are mutually exclusive", err.Error())
		assert.Nil(t, response)
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(nil, nil, types.ErrNotFound)

		response, err := ctx.client.GetDID(nil, GetDIDRequestObject{Did: id.String()})

		assert.ErrorIs(t, err, types.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, ctx.client.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(nil, nil, errors.New("b00m!"))

		response, err := ctx.client.GetDID(nil, GetDIDRequestObject{Did: id.String()})

		assert.Error(t, err)
		assert.Nil(t, response)
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
		ctx.vdr.EXPECT().ConflictedDocuments().Return([]did.Document{*didDoc}, []types.DocumentMetadata{*meta}, nil)

		response, err := ctx.client.ConflictedDIDs(nil, ConflictedDIDsRequestObject{})

		require.NoError(t, err)
		assert.Equal(t, *id, response.(ConflictedDIDs200JSONResponse)[0].Document.ID)
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vdr.EXPECT().ConflictedDocuments().Return(nil, nil, errors.New("b00m!"))

		response, err := ctx.client.ConflictedDIDs(nil, ConflictedDIDsRequestObject{})

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestWrapper_UpdateDID(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:1")
	didDoc := &did.Document{
		ID: *id,
	}
	request := DIDUpdateRequest{
		Document: *didDoc,
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vdr.EXPECT().Update(gomock.Any(), *id, gomock.Any()).Return(nil)

		response, err := ctx.client.UpdateDID(nil, UpdateDIDRequestObject{Did: id.String(), Body: &request})

		require.NoError(t, err)
		assert.Equal(t, *id, response.(UpdateDID200JSONResponse).ID)
	})

	t.Run("error - wrong did format", func(t *testing.T) {
		ctx := newMockContext(t)

		response, err := ctx.client.UpdateDID(nil, UpdateDIDRequestObject{Did: "not a did", Body: &request})

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.client.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vdr.EXPECT().Update(gomock.Any(), *id, gomock.Any()).Return(types.ErrNotFound)

		response, err := ctx.client.UpdateDID(nil, UpdateDIDRequestObject{Did: id.String(), Body: &request})

		assert.ErrorIs(t, err, types.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, ctx.client.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vdr.EXPECT().Update(gomock.Any(), *id, gomock.Any()).Return(errors.New("b00m!"))

		response, err := ctx.client.UpdateDID(nil, UpdateDIDRequestObject{Did: id.String(), Body: &request})

		assert.EqualError(t, err, "b00m!")
		assert.Nil(t, response)
	})

	t.Run("error - document deactivated", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vdr.EXPECT().Update(gomock.Any(), *id, gomock.Any()).Return(types.ErrDeactivated)

		response, err := ctx.client.UpdateDID(nil, UpdateDIDRequestObject{Did: id.String(), Body: &request})

		assert.ErrorIs(t, err, types.ErrDeactivated)
		assert.Equal(t, http.StatusConflict, ctx.client.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - did not managed by this node", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vdr.EXPECT().Update(gomock.Any(), *id, gomock.Any()).Return(types.ErrDIDNotManagedByThisNode)

		response, err := ctx.client.UpdateDID(nil, UpdateDIDRequestObject{Did: id.String(), Body: &request})

		assert.ErrorIs(t, err, types.ErrDIDNotManagedByThisNode)
		assert.Equal(t, http.StatusForbidden, ctx.client.ResolveStatusCode(err))
		assert.Nil(t, response)
	})
}

func TestWrapper_DeactivateDID(t *testing.T) {
	did123, _ := did.ParseDID("did:nuts:123")
	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().Deactivate(ctx.requestCtx, *did123).Return(nil)

		_, err := ctx.client.DeactivateDID(ctx.requestCtx, DeactivateDIDRequestObject{Did: did123.String()})

		assert.NoError(t, err)
	})

	t.Run("error - invalid DID format", func(t *testing.T) {
		ctx := newMockContext(t)

		_, err := ctx.client.DeactivateDID(ctx.requestCtx, DeactivateDIDRequestObject{Did: "not a did"})

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.client.ResolveStatusCode(err))
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.docUpdater.EXPECT().Deactivate(ctx.requestCtx, *did123).Return(types.ErrNotFound)

		_, err := ctx.client.DeactivateDID(ctx.requestCtx, DeactivateDIDRequestObject{Did: did123.String()})

		assert.ErrorIs(t, err, types.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, ctx.client.ResolveStatusCode(err))
	})

	t.Run("error - document already deactivated", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().Deactivate(ctx.requestCtx, *did123).Return(types.ErrDeactivated)

		_, err := ctx.client.DeactivateDID(ctx.requestCtx, DeactivateDIDRequestObject{Did: did123.String()})

		assert.ErrorIs(t, err, types.ErrDeactivated)
		assert.Equal(t, http.StatusConflict, ctx.client.ResolveStatusCode(err))
	})

	t.Run("error - did not managed by this node", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().Deactivate(ctx.requestCtx, *did123).Return(types.ErrDIDNotManagedByThisNode)

		_, err := ctx.client.DeactivateDID(ctx.requestCtx, DeactivateDIDRequestObject{Did: did123.String()})

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

		response, err := ctx.client.AddNewVerificationMethod(ctx.requestCtx, AddNewVerificationMethodRequestObject{Did: did123.String()})

		assert.NoError(t, err)
		assert.Equal(t, *newMethod, VerificationMethod(response.(AddNewVerificationMethod200JSONResponse)))
	})

	t.Run("ok - with key usage", func(t *testing.T) {
		ctx := newMockContext(t)
		expectedKeyUsage := didservice.DefaultCreationOptions().KeyFlags | types.AuthenticationUsage | types.CapabilityDelegationUsage
		ctx.docUpdater.EXPECT().AddVerificationMethod(ctx.requestCtx, *did123, expectedKeyUsage).Return(newMethod, nil)
		trueBool := true
		request := AddNewVerificationMethodJSONRequestBody{
			Authentication:       &trueBool,
			CapabilityDelegation: &trueBool,
		}

		response, err := ctx.client.AddNewVerificationMethod(ctx.requestCtx, AddNewVerificationMethodRequestObject{Did: did123.String(), Body: &request})

		assert.NoError(t, err)
		assert.Equal(t, *newMethod, VerificationMethod(response.(AddNewVerificationMethod200JSONResponse)))
	})

	t.Run("error - invalid did", func(t *testing.T) {
		ctx := newMockContext(t)

		response, err := ctx.client.AddNewVerificationMethod(ctx.requestCtx, AddNewVerificationMethodRequestObject{Did: "not a did"})

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.client.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - internal error", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().AddVerificationMethod(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("something went wrong"))

		response, err := ctx.client.AddNewVerificationMethod(ctx.requestCtx, AddNewVerificationMethodRequestObject{Did: did123.String()})

		assert.EqualError(t, err, "something went wrong")
		assert.Nil(t, response)
	})
}

func TestWrapper_DeleteVerificationMethod(t *testing.T) {
	did123, _ := did.ParseDID("did:nuts:123")
	did123Method, _ := did.ParseDIDURL("did:nuts:123#abc-method-1")

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().RemoveVerificationMethod(ctx.requestCtx, *did123, *did123Method).Return(nil)

		response, err := ctx.client.DeleteVerificationMethod(ctx.requestCtx, DeleteVerificationMethodRequestObject{Did: did123.String(), Kid: did123Method.String()})

		assert.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("error - invalid did", func(t *testing.T) {
		ctx := newMockContext(t)

		response, err := ctx.client.DeleteVerificationMethod(ctx.requestCtx, DeleteVerificationMethodRequestObject{Did: "not a did", Kid: did123Method.String()})

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Nil(t, response)
	})

	t.Run("error - invalid kid", func(t *testing.T) {
		ctx := newMockContext(t)

		response, err := ctx.client.DeleteVerificationMethod(ctx.requestCtx, DeleteVerificationMethodRequestObject{Did: did123.String(), Kid: "not a kid"})

		assert.EqualError(t, err, "given kid could not be parsed: invalid DID: input does not begin with 'did:' prefix")
		assert.Nil(t, response)
	})

	t.Run("error - internal error", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().RemoveVerificationMethod(ctx.requestCtx, *did123, *did123Method).Return(errors.New("something went wrong"))

		response, err := ctx.client.DeleteVerificationMethod(ctx.requestCtx, DeleteVerificationMethodRequestObject{Did: did123.String(), Kid: did123Method.String()})

		assert.EqualError(t, err, "could not remove verification method from document: something went wrong")
		assert.Nil(t, response)
	})
}

func Test_ErrorStatusCodes(t *testing.T) {
	assert.NotNil(t, (&Wrapper{}).ResolveStatusCode(nil))
}

type mockContext struct {
	ctrl        *gomock.Controller
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

	return mockContext{
		ctrl:        ctrl,
		vdr:         vdr,
		client:      client,
		docResolver: docResolver,
		docUpdater:  docManipulator,
		requestCtx:  requestCtx,
	}
}
