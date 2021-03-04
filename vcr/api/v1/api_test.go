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

package v1

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	did2 "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/stretchr/testify/assert"
)

func TestWrapper_CreateDID(t *testing.T) {
	u, _ := url.Parse("did:nuts:1")
	issuer := did2.URI{URL: *u}

	vc := did2.VerifiableCredential{
		Issuer: issuer,
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		var vcReturn *did2.VerifiableCredential
		ctx.echo.EXPECT().Bind(gomock.Any())
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			vcReturn = f2.(*did2.VerifiableCredential)
			return nil
		})
		ctx.vcr.EXPECT().Issue(gomock.Any()).Return(&vc, nil)
		err := ctx.client.Create(ctx.echo)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, issuer, vcReturn.Issuer)
	})

	t.Run("error - parse error", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())

		err := ctx.client.Create(ctx.echo)

		if !assert.NoError(t, err) {
			return
		}
	})

	t.Run("error - issue error", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any())
		ctx.vcr.EXPECT().Issue(gomock.Any()).Return(nil, errors.New("b00m!"))

		err := ctx.client.Create(ctx.echo)

		assert.Error(t, err)
	})

	t.Run("error - validation error", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any())
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())
		ctx.vcr.EXPECT().Issue(gomock.Any()).Return(nil, errors.New("validation failed"))

		err := ctx.client.Create(ctx.echo)

		assert.NoError(t, err)
	})
}

type mockContext struct {
	ctrl     *gomock.Controller
	echo     *mock.MockContext
	registry *concept.MockRegistry
	vcr      *vcr.MockVCR
	client   *Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	registry := concept.NewMockRegistry(ctrl)
	vcr := vcr.NewMockVCR(ctrl)
	client := &Wrapper{CR: registry, R: vcr}

	return mockContext{
		ctrl:     ctrl,
		echo:     mock.NewMockContext(ctrl),
		registry: registry,
		vcr:      vcr,
		client:   client,
	}
}
