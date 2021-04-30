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

package didman

import (
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
)

func TestDidman_Name(t *testing.T) {
	instance := NewDidmanInstance(nil, nil).(core.Named)

	assert.Equal(t, ModuleName, instance.Name())
}

func TestNewDidmanInstance(t *testing.T) {
	ctx := newMockContext(t)
	instance := NewDidmanInstance(ctx.docResolver, ctx.vdr).(*didman)

	assert.NotNil(t, instance)
	assert.Equal(t, ctx.docResolver, instance.docResolver)
	assert.Equal(t, ctx.vdr, instance.vdr)
}

func TestDidman_AddEndpoint(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/v1")
	meta := &types.DocumentMetadata{Hash: hash.EmptyHash()}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		doc := &did.Document{}
		var newDoc did.Document
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, nil).Return(doc, meta, nil)
		ctx.vdr.EXPECT().Update(*vdr.TestDIDA, meta.Hash, gomock.Any(), nil).DoAndReturn(
			func(_ interface{}, _ interface{}, doc interface{}, _ interface{}) error {
				newDoc = doc.(did.Document)
				return nil
			})

		err := ctx.instance.AddEndpoint(*vdr.TestDIDA, "type", *u)

		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, newDoc.Service, 1)
		assert.Equal(t, "type", newDoc.Service[0].Type)
		assert.Equal(t, u.String(), newDoc.Service[0].ServiceEndpoint)
		assert.Contains(t, newDoc.Service[0].ID.String(), vdr.TestDIDA.String())
	})

	t.Run("error - update failed", func(t *testing.T) {
		ctx := newMockContext(t)
		doc := &did.Document{}
		returnError := errors.New("b00m!")
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, nil).Return(doc, meta, nil)
		ctx.vdr.EXPECT().Update(*vdr.TestDIDA, meta.Hash, gomock.Any(), nil).Return(returnError)

		err := ctx.instance.AddEndpoint(*vdr.TestDIDA, "type", *u)

		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, returnError, err)
	})

	t.Run("error - duplicate service", func(t *testing.T) {
		ctx := newMockContext(t)
		doc := &did.Document{}
		returnError := errors.New("b00m!")
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, nil).Return(doc, meta, nil).Times(2)
		ctx.vdr.EXPECT().Update(*vdr.TestDIDA, meta.Hash, gomock.Any(), nil).Return(returnError)

		_ = ctx.instance.AddEndpoint(*vdr.TestDIDA, "type", *u)
		err := ctx.instance.AddEndpoint(*vdr.TestDIDA, "type", *u)

		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, ErrDuplicateService, err)
	})

	t.Run("error - DID not found", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := NewDidmanInstance(ctx.docResolver, ctx.vdr)
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, nil).Return(nil, nil, types.ErrNotFound)

		err := instance.AddEndpoint(*vdr.TestDIDA, "type", *u)

		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, types.ErrNotFound, err)
	})
}

func TestConstructService(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/v1")
	expectedID, _ := ssi.ParseURI(fmt.Sprintf("%s#D4eNCVjdtGaeHYMdjsdYHpTQmiwXtQKJmE9QSwwsKKzy", vdr.TestDIDA.String()))

	service := constructService(*vdr.TestDIDA, "type", *u)

	assert.Equal(t, "type", service.Type)
	assert.Equal(t, u.String(), service.ServiceEndpoint)
	assert.Equal(t, *expectedID, service.ID)
}

type mockContext struct {
	ctrl        *gomock.Controller
	docResolver *types.MockDocResolver
	vdr         *types.MockVDR
	instance    Didman
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	t.Cleanup(func() {
		ctrl.Finish()
	})
	docResolver := types.NewMockDocResolver(ctrl)
	vdr := types.NewMockVDR(ctrl)
	instance := NewDidmanInstance(docResolver, vdr)

	return mockContext{
		ctrl:        ctrl,
		docResolver: docResolver,
		vdr:         vdr,
		instance:    instance,
	}
}
