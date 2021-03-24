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
	"errors"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

func TestWrapper_CreateDID(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:1")
	didDoc := &did.Document{
		ID: *id,
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		var didDocReturn did.Document
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			didDocReturn = f2.(did.Document)
			return nil
		})
		ctx.vdr.EXPECT().Create().Return(didDoc, nil)
		err := ctx.client.CreateDID(ctx.echo)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, *id, didDocReturn.ID)
	})

	t.Run("error - 500", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vdr.EXPECT().Create().Return(nil, errors.New("b00m!"))
		err := ctx.client.CreateDID(ctx.echo)

		assert.Error(t, err)
	})
}

func TestWrapper_GetDID(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:1")
	didDoc := &did.Document{
		ID: *id,
	}
	meta := &types.DocumentMetadata{}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		didResolutionResult := DIDResolutionResult{}
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			didResolutionResult = f2.(DIDResolutionResult)
			return nil
		})

		ctx.vdr.EXPECT().Resolve(*id, nil).Return(didDoc, meta, nil)
		err := ctx.client.GetDID(ctx.echo, id.String())

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, *id, didResolutionResult.Document.ID)
	})

	t.Run("error - wrong did format", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())
		err := ctx.client.GetDID(ctx.echo, "not a did")

		assert.NoError(t, err)
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().NoContent(http.StatusNotFound)
		ctx.vdr.EXPECT().Resolve(*id, nil).Return(nil, nil, types.ErrNotFound)
		err := ctx.client.GetDID(ctx.echo, id.String())

		assert.NoError(t, err)
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vdr.EXPECT().Resolve(*id, nil).Return(nil, nil, errors.New("b00m!"))
		err := ctx.client.GetDID(ctx.echo, id.String())

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
		defer ctx.ctrl.Finish()

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
		ctx.vdr.EXPECT().Update(*id, gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		err := ctx.client.UpdateDID(ctx.echo, id.String())

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, *id, didReturn.ID)
	})

	t.Run("error - wrong did format", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())
		err := ctx.client.UpdateDID(ctx.echo, "not a did")

		assert.NoError(t, err)
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDUpdateRequest)
			*p = didUpdate
			return nil
		})
		ctx.echo.EXPECT().NoContent(http.StatusNotFound)
		ctx.vdr.EXPECT().Update(*id, gomock.Any(), gomock.Any(), gomock.Any()).Return(types.ErrNotFound)
		err := ctx.client.UpdateDID(ctx.echo, id.String())

		assert.NoError(t, err)
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDUpdateRequest)
			*p = didUpdate
			return nil
		})
		ctx.echo.EXPECT().String(http.StatusInternalServerError, gomock.Any())
		ctx.vdr.EXPECT().Update(*id, gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("b00m!"))
		err := ctx.client.UpdateDID(ctx.echo, id.String())

		assert.NoError(t, err)
	})

	t.Run("error - wrong hash", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		didUpdate := DIDUpdateRequest{
			Document:    *didDoc,
			CurrentHash: "0",
		}

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDUpdateRequest)
			*p = didUpdate
			return nil
		})
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())
		err := ctx.client.UpdateDID(ctx.echo, id.String())

		assert.NoError(t, err)
	})

	t.Run("error - bind goes wrong", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())
		err := ctx.client.UpdateDID(ctx.echo, id.String())

		assert.NoError(t, err)
	})

	t.Run("error - document deactivated", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDUpdateRequest)
			*p = didUpdate
			return nil
		})

		ctx.echo.EXPECT().String(http.StatusConflict, "could not update document: the document has been deactivated")
		ctx.vdr.EXPECT().Update(*id, gomock.Any(), gomock.Any(), gomock.Any()).Return(types.ErrDeactivated)

		err := ctx.client.UpdateDID(ctx.echo, id.String())
		assert.NoError(t, err)
	})

	t.Run("error - did not managed by this node", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDUpdateRequest)
			*p = didUpdate
			return nil
		})

		ctx.echo.EXPECT().String(http.StatusForbidden, "could not update document: DID document not managed by this node")
		ctx.vdr.EXPECT().Update(*id, gomock.Any(), gomock.Any(), gomock.Any()).Return(types.ErrDIDNotManagedByThisNode)

		err := ctx.client.UpdateDID(ctx.echo, id.String())
		assert.NoError(t, err)
	})
}

func TestWrapper_DeactivateDID(t *testing.T) {
	did123, _ := did.ParseDID("did:nuts:123")
	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().Deactivate(*did123).Return(nil)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().NoContent(http.StatusOK)
		err := ctx.client.DeactivateDID(ctx.echo, did123.String())
		assert.NoError(t, err)
	})

	t.Run("error - invalid DID format", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().String(http.StatusBadRequest, "given DID could not be parsed: input does not begin with 'did:' prefix")
		err := ctx.client.DeactivateDID(ctx.echo, "invalidFormattedDID")
		assert.NoError(t, err)
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.docUpdater.EXPECT().Deactivate(*did123).Return(types.ErrNotFound)
		ctx.echo.EXPECT().NoContent(http.StatusNotFound)

		err := ctx.client.DeactivateDID(ctx.echo, did123.String())
		assert.NoError(t, err)
	})

	t.Run("error - document already deactivated", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().Deactivate(*did123).Return(types.ErrDeactivated)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().String(http.StatusConflict, "could not deactivate document: the document has been deactivated")
		err := ctx.client.DeactivateDID(ctx.echo, did123.String())
		assert.NoError(t, err)
	})

	t.Run("error - did not managed by this node", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().Deactivate(*did123).Return(types.ErrDIDNotManagedByThisNode)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().String(http.StatusForbidden, "could not deactivate document: DID document not managed by this node")
		err := ctx.client.DeactivateDID(ctx.echo, did123.String())
		assert.NoError(t, err)
	})
}

type mockContext struct {
	ctrl       *gomock.Controller
	echo       *mock.MockContext
	vdr        *types.MockVDR
	docUpdater *types.MockDocManipulator
	client     *Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	vdr := types.NewMockVDR(ctrl)
	docManipulator := types.NewMockDocManipulator(ctrl)
	client := &Wrapper{VDR: vdr, DocManipulator: docManipulator}

	return mockContext{
		ctrl:       ctrl,
		echo:       mock.NewMockContext(ctrl),
		vdr:        vdr,
		client:     client,
		docUpdater: docManipulator,
	}
}
