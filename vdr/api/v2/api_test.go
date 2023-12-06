/*
 * Nuts node
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

package v2

import (
	"context"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestWrapper_CreateDID(t *testing.T) {
	id := did.MustParseDID("did:web:example.com:iam:1")
	didDoc := &did.Document{
		ID: id,
	}

	t.Run("ok - defaults", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vdr.EXPECT().Create(gomock.Any(), didweb.MethodName, gomock.Any()).Return(didDoc, nil, nil)

		response, err := ctx.client.CreateDID(nil, CreateDIDRequestObject{})

		require.NoError(t, err)
		assert.Equal(t, id, response.(CreateDID200JSONResponse).ID)
	})

	t.Run("error - create fails", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vdr.EXPECT().Create(gomock.Any(), didweb.MethodName, gomock.Any()).Return(nil, nil, assert.AnError)

		response, err := ctx.client.CreateDID(nil, CreateDIDRequestObject{})

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

type mockContext struct {
	ctrl        *gomock.Controller
	vdr         *vdr.MockVDR
	didResolver *resolver.MockDIDResolver
	client      *Wrapper
	requestCtx  context.Context
}

func newMockContext(t *testing.T) mockContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	didResolver := resolver.NewMockDIDResolver(ctrl)
	vdr := vdr.NewMockVDR(ctrl)
	vdr.EXPECT().Resolver().Return(didResolver).AnyTimes()
	client := &Wrapper{VDR: vdr}
	requestCtx := audit.TestContext()

	return mockContext{
		ctrl:        ctrl,
		vdr:         vdr,
		didResolver: didResolver,
		client:      client,
		requestCtx:  requestCtx,
	}
}
