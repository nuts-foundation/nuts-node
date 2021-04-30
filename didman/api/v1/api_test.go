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
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
)

func TestWrapper_AddEndpoint(t *testing.T) {
	id := "did:nuts:1"
	request := EndpointCreateRequest{
		Endpoint: "https://api.example.com/v1",
		Type:     "type",
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		var (
			parsedDID  did.DID
			parsedURL  url.URL
			parsedType string
		)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointCreateRequest)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddEndpoint(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(id interface{}, t interface{}, u interface{}) error {
				parsedDID = id.(did.DID)
				parsedURL = u.(url.URL)
				parsedType = t.(string)
				return nil
			})
		ctx.echo.EXPECT().NoContent(http.StatusNoContent).Return(nil)

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, id, parsedDID.String())
		assert.Equal(t, request.Endpoint, parsedURL.String())
		assert.Equal(t, request.Type, parsedType)
	})

	t.Run("error - incorrect type", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointCreateRequest)
			*p = EndpointCreateRequest{Endpoint: "https://api.example.com/v1"}
			return nil
		})
		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test.AssertErrProblemDetail(t, "invalid value for type", err)
	})

	t.Run("error - incorrect endpoint", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointCreateRequest)
			*p = EndpointCreateRequest{Type: "type", Endpoint: ":"}
			return nil
		})
		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test.AssertErrProblemDetail(t, "invalid value for endpoint: parse \":\": missing protocol scheme", err)
	})

	t.Run("error - incorrect did", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointCreateRequest)
			*p = request
			return nil
		})
		err := ctx.wrapper.AddEndpoint(ctx.echo, "")

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test.AssertErrProblemDetail(t, "failed to parse DID: input length is less than 7", err)
	})

	t.Run("error - DID not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointCreateRequest)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddEndpoint(gomock.Any(), gomock.Any(), gomock.Any()).Return(types.ErrNotFound)

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusNotFound, err)
	})

	t.Run("error - incorrect post body", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
	})

	t.Run("error - deactivated", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointCreateRequest)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddEndpoint(gomock.Any(), gomock.Any(), gomock.Any()).Return(types.ErrDeactivated)

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusConflict, err)
		test.AssertErrProblemDetail(t, types.ErrDeactivated.Error(), err)
	})

	t.Run("error - not managed", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointCreateRequest)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddEndpoint(gomock.Any(), gomock.Any(), gomock.Any()).Return(types.ErrDIDNotManagedByThisNode)

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test.AssertErrProblemDetail(t, types.ErrDIDNotManagedByThisNode.Error(), err)
	})

	t.Run("error - duplicate", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointCreateRequest)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddEndpoint(gomock.Any(), gomock.Any(), gomock.Any()).Return(didman.ErrDuplicateService)

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusConflict, err)
		test.AssertErrProblemDetail(t, didman.ErrDuplicateService.Error(), err)
	})
}

type mockContext struct {
	ctrl    *gomock.Controller
	echo    *mock.MockContext
	didman  *didman.MockDidman
	wrapper Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	t.Cleanup(func() {
		ctrl.Finish()
	})
	didman := didman.NewMockDidman(ctrl)

	return mockContext{
		ctrl:    ctrl,
		echo:    mock.NewMockContext(ctrl),
		didman:  didman,
		wrapper: Wrapper{didman},
	}
}
