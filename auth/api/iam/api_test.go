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

package iam

import (
	"errors"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/core"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
)

func TestWrapper_GetOAuthAuthorizationServerMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		//	200
		ctx := newTestClient(t)
		did := did.MustParseDID("did:nuts:123")
		ctx.documentOwner.EXPECT().IsOwner(nil, did).Return(true, nil)

		res, err := ctx.client.GetOAuthAuthorizationServerMetadata(nil, GetOAuthAuthorizationServerMetadataRequestObject{Did: did.String()})

		require.NoError(t, err)
		assert.IsType(t, GetOAuthAuthorizationServerMetadata200JSONResponse{}, res)

	})
	t.Run("error - not a did", func(t *testing.T) {
		//400
		ctx := newTestClient(t)

		res, err := ctx.client.GetOAuthAuthorizationServerMetadata(nil, GetOAuthAuthorizationServerMetadataRequestObject{})

		assert.Equal(t, 400, statusCodeFrom(err))
		assert.EqualError(t, err, "authz server metadata: invalid DID")
		assert.Nil(t, res)
	})
	t.Run("error - not a did:nuts", func(t *testing.T) {
		//400
		ctx := newTestClient(t)

		res, err := ctx.client.GetOAuthAuthorizationServerMetadata(nil, GetOAuthAuthorizationServerMetadataRequestObject{Did: "did:web:example.com"})

		assert.Equal(t, 400, statusCodeFrom(err))
		assert.EqualError(t, err, "authz server metadata: only did:nuts is supported")
		assert.Nil(t, res)
	})
	t.Run("error - did not managed by this node", func(t *testing.T) {
		//404
		ctx := newTestClient(t)
		did := did.MustParseDID("did:nuts:123")
		ctx.documentOwner.EXPECT().IsOwner(nil, did)

		res, err := ctx.client.GetOAuthAuthorizationServerMetadata(nil, GetOAuthAuthorizationServerMetadataRequestObject{Did: did.String()})

		assert.Equal(t, 404, statusCodeFrom(err))
		assert.EqualError(t, err, "authz server metadata: did not owned")
		assert.Nil(t, res)
	})
	t.Run("error - did does not exist", func(t *testing.T) {
		//404
		ctx := newTestClient(t)
		did := did.MustParseDID("did:nuts:123")
		ctx.documentOwner.EXPECT().IsOwner(nil, did).Return(false, vdr.ErrNotFound)

		res, err := ctx.client.GetOAuthAuthorizationServerMetadata(nil, GetOAuthAuthorizationServerMetadataRequestObject{Did: did.String()})

		assert.Equal(t, 404, statusCodeFrom(err))
		assert.EqualError(t, err, "authz server metadata: unable to find the DID document")
		assert.Nil(t, res)
	})
	t.Run("error - internal error 500", func(t *testing.T) {
		//500
		ctx := newTestClient(t)
		did := did.MustParseDID("did:nuts:123")
		ctx.documentOwner.EXPECT().IsOwner(nil, did).Return(false, errors.New("unknown error"))

		res, err := ctx.client.GetOAuthAuthorizationServerMetadata(nil, GetOAuthAuthorizationServerMetadataRequestObject{Did: did.String()})

		assert.Equal(t, 500, statusCodeFrom(err))
		assert.EqualError(t, err, "authz server metadata: unknown error")
		assert.Nil(t, res)
	})
}

// statusCodeFrom returns the statuscode if err is core.HTTPStatusCodeError, or 0 if it isn't
func statusCodeFrom(err error) int {
	var SE core.HTTPStatusCodeError
	if errors.As(err, &SE) {
		return SE.StatusCode()
	}
	return 0
}

type testCtx struct {
	client        *Wrapper
	documentOwner *vdr.MockDocumentOwner
}

func newTestClient(t testing.TB) *testCtx {
	ctrl := gomock.NewController(t)
	ctx := &testCtx{
		documentOwner: vdr.NewMockDocumentOwner(ctrl),
	}
	ctx.client = &Wrapper{
		auth: auth.NewAuthInstance(auth.Config{PublicURL: "https://example.com"}, nil, nil, nil, nil, nil, nil),
		vdr:  ctx.documentOwner,
	}
	return ctx
}
