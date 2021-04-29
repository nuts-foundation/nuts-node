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
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

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
		ctx.vdr.EXPECT().Create(gomock.Any()).Return(didDoc, nil, nil)
		err := ctx.client.CreateDID(ctx.echo)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, *id, didDocReturn.ID)
	})

	t.Run("ok - non defaults", func(t *testing.T) {
		ctx := newMockContext(t)

		var didDocReturn did.Document
		varTrue := true
		varFalse := false
		controllers := []string{"did:nuts:2"}
		didCreateRequest := DIDCreateRequest{
			AssertionMethod:       &varFalse,
			Authentication:        &varTrue,
			CapablilityDelegation: &varTrue,
			CapablilityInvocation: &varFalse,
			KeyAgreement:          &varTrue,
			SelfControl:           &varFalse,
			Controllers: 		   &controllers,
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
		ctx.vdr.EXPECT().Create(gomock.Any()).Return(didDoc, nil, nil)
		err := ctx.client.CreateDID(ctx.echo)

		if !assert.NoError(t, err) {
			return
		}
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
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any()).Return(nil)
		err := ctx.client.CreateDID(ctx.echo)

		assert.NoError(t, err)
	})

	t.Run("error - invalid options", func(t *testing.T) {
		ctx := newMockContext(t)

		didCreateRequest := DIDCreateRequest{}
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDCreateRequest)
			*p = didCreateRequest
			return nil
		})
		ctx.vdr.EXPECT().Create(gomock.Any()).Return(nil, nil, doc.ErrInvalidOptions)
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any()).Return(nil)
		err := ctx.client.CreateDID(ctx.echo)

		assert.NoError(t, err)
	})

	t.Run("error - 500", func(t *testing.T) {
		ctx := newMockContext(t)

		didCreateRequest := DIDCreateRequest{}
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDCreateRequest)
			*p = didCreateRequest
			return nil
		})
		ctx.vdr.EXPECT().Create(gomock.Any()).Return(nil, nil, errors.New("b00m!"))
		err := ctx.client.CreateDID(ctx.echo)

		assert.Error(t, err)
	})

	t.Run("error - bind fails", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any()).Return(nil)
		err := ctx.client.CreateDID(ctx.echo)

		assert.NoError(t, err)
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

		didResolutionResult := DIDResolutionResult{}
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			didResolutionResult = f2.(DIDResolutionResult)
			return nil
		})

		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, meta, nil)
		err := ctx.client.GetDID(ctx.echo, id.String())

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, *id, didResolutionResult.Document.ID)
	})

	t.Run("error - wrong did format", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())
		err := ctx.client.GetDID(ctx.echo, "not a did")

		assert.NoError(t, err)
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().String(http.StatusNotFound, "DID document not found")
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(nil, nil, types.ErrNotFound)
		err := ctx.client.GetDID(ctx.echo, id.String())

		assert.NoError(t, err)
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(nil, nil, errors.New("b00m!"))
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

		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())
		err := ctx.client.UpdateDID(ctx.echo, "not a did")

		assert.NoError(t, err)
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDUpdateRequest)
			*p = didUpdate
			return nil
		})
		ctx.echo.EXPECT().String(http.StatusNotFound, "could not update DID document: unable to find the DID document")
		ctx.vdr.EXPECT().Update(*id, gomock.Any(), gomock.Any(), gomock.Any()).Return(types.ErrNotFound)
		err := ctx.client.UpdateDID(ctx.echo, id.String())

		assert.NoError(t, err)
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)

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

		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())
		err := ctx.client.UpdateDID(ctx.echo, id.String())

		assert.NoError(t, err)
	})

	t.Run("error - document deactivated", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDUpdateRequest)
			*p = didUpdate
			return nil
		})

		ctx.echo.EXPECT().String(http.StatusConflict, "could not update DID document: the DID document has been deactivated")
		ctx.vdr.EXPECT().Update(*id, gomock.Any(), gomock.Any(), gomock.Any()).Return(types.ErrDeactivated)

		err := ctx.client.UpdateDID(ctx.echo, id.String())
		assert.NoError(t, err)
	})

	t.Run("error - did not managed by this node", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*DIDUpdateRequest)
			*p = didUpdate
			return nil
		})

		ctx.echo.EXPECT().String(http.StatusForbidden, "could not update DID document: DID document not managed by this node")
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

		ctx.echo.EXPECT().NoContent(http.StatusOK)
		err := ctx.client.DeactivateDID(ctx.echo, did123.String())
		assert.NoError(t, err)
	})

	t.Run("error - invalid DID format", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().String(http.StatusBadRequest, "given DID could not be parsed: input does not begin with 'did:' prefix")
		err := ctx.client.DeactivateDID(ctx.echo, "invalidFormattedDID")
		assert.NoError(t, err)
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.docUpdater.EXPECT().Deactivate(*did123).Return(types.ErrNotFound)
		ctx.echo.EXPECT().String(http.StatusNotFound, "could not deactivate DID document: unable to find the DID document")

		err := ctx.client.DeactivateDID(ctx.echo, did123.String())
		assert.NoError(t, err)
	})

	t.Run("error - document already deactivated", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().Deactivate(*did123).Return(types.ErrDeactivated)

		ctx.echo.EXPECT().String(http.StatusConflict, "could not deactivate DID document: the DID document has been deactivated")
		err := ctx.client.DeactivateDID(ctx.echo, did123.String())
		assert.NoError(t, err)
	})

	t.Run("error - did not managed by this node", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().Deactivate(*did123).Return(types.ErrDIDNotManagedByThisNode)

		ctx.echo.EXPECT().String(http.StatusForbidden, "could not deactivate DID document: DID document not managed by this node")
		err := ctx.client.DeactivateDID(ctx.echo, did123.String())
		assert.NoError(t, err)
	})
}

func TestWrapper_AddNewVerificationMethod(t *testing.T) {
	did123, _ := did.ParseDID("did:nuts:123")
	did123Method, _ := did.ParseDID("did:nuts:123#abc-method-1")

	newMethod := &did.VerificationMethod{ID: *did123Method}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().AddVerificationMethod(*did123).Return(newMethod, nil)

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

		ctx.echo.EXPECT().String(http.StatusBadRequest, "given DID could not be parsed: input does not begin with 'did:' prefix")
		err := ctx.client.AddNewVerificationMethod(ctx.echo, "not a did")
		assert.NoError(t, err)
	})

	t.Run("error - internal error", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().AddVerificationMethod(*did123).Return(nil, errors.New("something went wrong"))

		ctx.echo.EXPECT().String(http.StatusInternalServerError, "could not update DID document: something went wrong")
		err := ctx.client.AddNewVerificationMethod(ctx.echo, did123.String())
		assert.NoError(t, err)
	})
}

func TestWrapper_DeleteVerificationMethod(t *testing.T) {
	did123, _ := did.ParseDID("did:nuts:123")
	did123Method, _ := did.ParseDID("did:nuts:123#abc-method-1")

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().RemoveVerificationMethod(*did123, *did123Method).Return(nil)
		ctx.echo.EXPECT().NoContent(http.StatusNoContent)

		err := ctx.client.DeleteVerificationMethod(ctx.echo, did123.String(), did123Method.String())
		assert.NoError(t, err)
	})

	t.Run("error - invalid did", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().String(http.StatusBadRequest, "given DID could not be parsed: input does not begin with 'did:' prefix")
		err := ctx.client.DeleteVerificationMethod(ctx.echo, "invalid did", did123Method.String())
		assert.NoError(t, err)
	})

	t.Run("error - invalid kid", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.echo.EXPECT().String(http.StatusBadRequest, "given kid could not be parsed: input does not begin with 'did:' prefix")
		err := ctx.client.DeleteVerificationMethod(ctx.echo, did123.String(), "invalid kid")
		assert.NoError(t, err)
	})

	t.Run("error - internal error", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docUpdater.EXPECT().RemoveVerificationMethod(*did123, *did123Method).Return(errors.New("something went wrong"))

		ctx.echo.EXPECT().String(http.StatusInternalServerError, "could not remove verification method from document: something went wrong")
		err := ctx.client.DeleteVerificationMethod(ctx.echo, did123.String(), did123Method.String())
		assert.NoError(t, err)
	})
}

func Test_handleError(t *testing.T) {
	t.Run("unknown error causes 500", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().String(http.StatusInternalServerError, "template: error!!")
		err := handleError(ctx.echo, errors.New("error!!"), "template: %s")
		assert.NoError(t, err)
	})

	t.Run("not found error causes 404", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().String(http.StatusNotFound, "template: unable to find the DID document")
		err := handleError(ctx.echo, types.ErrNotFound, "template: %s")
		assert.NoError(t, err)
	})
	t.Run("not managed error causes 403", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().String(http.StatusForbidden, "template: DID document not managed by this node")
		err := handleError(ctx.echo, types.ErrDIDNotManagedByThisNode, "template: %s")
		assert.NoError(t, err)
	})
	t.Run("deactivated error causes 409", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().String(http.StatusConflict, "template: the DID document has been deactivated")
		err := handleError(ctx.echo, types.ErrDeactivated, "template: %s")
		assert.NoError(t, err)
	})

	t.Run("no error causes no error", func(t *testing.T) {
		ctx := newMockContext(t)
		err := handleError(ctx.echo, nil, "template: %s")
		assert.NoError(t, err)
	})
}

type mockContext struct {
	ctrl        *gomock.Controller
	echo        *mock.MockContext
	vdr         *types.MockVDR
	docResolver *types.MockDocResolver
	docUpdater  *types.MockDocManipulator
	client      *Wrapper
}

func newMockContext(t *testing.T) mockContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	vdr := types.NewMockVDR(ctrl)
	docManipulator := types.NewMockDocManipulator(ctrl)
	docResolver := types.NewMockDocResolver(ctrl)
	client := &Wrapper{VDR: vdr, DocManipulator: docManipulator, DocResolver: docResolver}

	t.Cleanup(func() {
		ctrl.Finish()
	})
	return mockContext{
		ctrl:        ctrl,
		echo:        mock.NewMockContext(ctrl),
		vdr:         vdr,
		client:      client,
		docResolver: docResolver,
		docUpdater:  docManipulator,
	}
}
