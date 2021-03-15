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
	did2 "github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

func TestWrapper_CreateDID(t *testing.T) {
	did, _ := did2.ParseDID("did:nuts:1")
	didDoc := &did2.Document{
		ID: *did,
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		var didDocReturn did2.Document
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			didDocReturn = f2.(did2.Document)
			return nil
		})
		ctx.vdr.EXPECT().Create().Return(didDoc, nil)
		err := ctx.client.CreateDID(ctx.echo)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, *did, didDocReturn.ID)
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
	did, _ := did2.ParseDID("did:nuts:1")
	didDoc := &did2.Document{
		ID: *did,
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

		ctx.vdr.EXPECT().Resolve(*did, nil).Return(didDoc, meta, nil)
		err := ctx.client.GetDID(ctx.echo, did.String())

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, *did, didResolutionResult.Document.ID)
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
		ctx.vdr.EXPECT().Resolve(*did, nil).Return(nil, nil, types.ErrNotFound)
		err := ctx.client.GetDID(ctx.echo, did.String())

		assert.NoError(t, err)
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vdr.EXPECT().Resolve(*did, nil).Return(nil, nil, errors.New("b00m!"))
		err := ctx.client.GetDID(ctx.echo, did.String())

		assert.Error(t, err)
	})
}

func TestWrapper_UpdateDID(t *testing.T) {
	did, _ := did2.ParseDID("did:nuts:1")
	didDoc := &did2.Document{
		ID: *did,
	}
	didUpdate := DIDUpdateRequest{
		Document:    *didDoc,
		CurrentHash: "452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620",
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		var didReturn did2.Document
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDUpdateRequest)
			*p = didUpdate
			return nil
		})
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			didReturn = f2.(did2.Document)
			return nil
		})
		ctx.vdr.EXPECT().Update(*did, gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		err := ctx.client.UpdateDID(ctx.echo, did.String())

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, *did, didReturn.ID)
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
		ctx.vdr.EXPECT().Update(*did, gomock.Any(), gomock.Any(), gomock.Any()).Return(types.ErrNotFound)
		err := ctx.client.UpdateDID(ctx.echo, did.String())

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
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())
		ctx.vdr.EXPECT().Update(*did, gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("b00m!"))
		err := ctx.client.UpdateDID(ctx.echo, did.String())

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
		err := ctx.client.UpdateDID(ctx.echo, did.String())

		assert.NoError(t, err)
	})

	t.Run("error - bind goes wrong", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())
		err := ctx.client.UpdateDID(ctx.echo, did.String())

		assert.NoError(t, err)
	})
}

func TestWrapper_DeactivateDID(t *testing.T) {
	did123, _ := did2.ParseDID("did:nuts:123")
	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vdr.EXPECT().Deactivate(*did123).Return(nil)
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
		ctx.vdr.EXPECT().Deactivate(*did123).Return(types.ErrNotFound)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().NoContent(http.StatusNotFound)
		err := ctx.client.DeactivateDID(ctx.echo, did123.String())
		assert.NoError(t, err)
	})

	t.Run("error - document already deactivated", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vdr.EXPECT().Deactivate(*did123).Return(types.ErrDeactivated)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().String(http.StatusBadRequest, "could not deactivate document: the document has been deactivated")
		err := ctx.client.DeactivateDID(ctx.echo, did123.String())
		assert.NoError(t, err)
	})
}

type mockContext struct {
	ctrl   *gomock.Controller
	echo   *mock.MockContext
	vdr    *types.MockVDR
	client *Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	vdr := types.NewMockVDR(ctrl)
	client := &Wrapper{VDR: vdr}

	return mockContext{
		ctrl:   ctrl,
		echo:   mock.NewMockContext(ctrl),
		vdr:    vdr,
		client: client,
	}
}
