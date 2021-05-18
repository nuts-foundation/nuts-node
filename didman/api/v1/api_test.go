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
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
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
		test.AssertErrProblemTitle(t, problemTitleAddEndpoint, err)
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
		test.AssertErrProblemTitle(t, problemTitleAddEndpoint, err)
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
		test.AssertErrProblemTitle(t, problemTitleAddEndpoint, err)
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
		test.AssertErrProblemTitle(t, problemTitleAddEndpoint, err)
	})

	t.Run("error - incorrect post body", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test.AssertErrProblemTitle(t, problemTitleAddEndpoint, err)
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
		test.AssertErrProblemTitle(t, problemTitleAddEndpoint, err)
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
		test.AssertErrProblemTitle(t, problemTitleAddEndpoint, err)
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
		test.AssertErrProblemTitle(t, problemTitleAddEndpoint, err)
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointCreateRequest)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddEndpoint(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("b00m!"))

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusInternalServerError, err)
		test.AssertErrProblemTitle(t, problemTitleAddEndpoint, err)
	})
}

func TestWrapper_AddCompoundService(t *testing.T) {
	id := "did:nuts:1"
	request := CompoundServiceCreateRequest{
		Endpoint: map[string]interface{}{
			"foo": "did:nuts:12345?type=foo",
			"bar": "did:nuts:54321?type=bar",
		},
		Type: "type",
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		var (
			parsedDID      did.DID
			parsedEndpoint map[string]ssi.URI
			parsedType     string
		)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*CompoundServiceCreateRequest)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddCompoundService(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(subject interface{}, endpointType interface{}, endpoint interface{}) error {
				parsedDID = subject.(did.DID)
				parsedEndpoint = endpoint.(map[string]ssi.URI)
				parsedType = endpointType.(string)
				return nil
			})
		ctx.echo.EXPECT().NoContent(http.StatusNoContent).Return(nil)

		err := ctx.wrapper.AddCompoundService(ctx.echo, id)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, id, parsedDID.String())
		assert.Len(t, parsedEndpoint, 2)
		assert.Equal(t, request.Endpoint["foo"], parsedEndpoint["foo"].String())
		assert.Equal(t, request.Endpoint["bar"], parsedEndpoint["bar"].String())
		assert.Equal(t, request.Type, parsedType)
	})

	t.Run("error - service fails", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*CompoundServiceCreateRequest)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddCompoundService(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("failed"))

		err := ctx.wrapper.AddCompoundService(ctx.echo, id)
		test.AssertErrProblemStatusCode(t, http.StatusInternalServerError, err)
		test.AssertErrProblemDetail(t,  "failed", err)
		test.AssertErrProblemTitle(t, problemTitleAddCompoundService, err)
	})

	t.Run("error - incorrect endpoint (not a URI)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*CompoundServiceCreateRequest)
			*p = CompoundServiceCreateRequest{Type: "type", Endpoint: map[string]interface{}{"foo": ":"}}
			return nil
		})
		err := ctx.wrapper.AddCompoundService(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test.AssertErrProblemDetail(t,  "invalid reference for service 'foo': parse \":\": missing protocol scheme", err)
		test.AssertErrProblemTitle(t, problemTitleAddCompoundService, err)
	})

	t.Run("error - incorrect endpoint (not a string)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*CompoundServiceCreateRequest)
			*p = CompoundServiceCreateRequest{Type: "type", Endpoint: map[string]interface{}{"foo": map[string]interface{}{}}}
			return nil
		})
		err := ctx.wrapper.AddCompoundService(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test.AssertErrProblemDetail(t,  "invalid reference for service 'foo': not a string", err)
		test.AssertErrProblemTitle(t, problemTitleAddCompoundService, err)
	})

	t.Run("error - incorrect did", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*CompoundServiceCreateRequest)
			*p = request
			return nil
		})
		err := ctx.wrapper.AddCompoundService(ctx.echo, "")

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test.AssertErrProblemDetail(t, "failed to parse DID: input length is less than 7", err)
		test.AssertErrProblemTitle(t, problemTitleAddCompoundService, err)
	})

	t.Run("error - incorrect post body", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))

		err := ctx.wrapper.AddCompoundService(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test.AssertErrProblemTitle(t, problemTitleAddCompoundService, err)
	})
}

func TestWrapper_DeleteService(t *testing.T) {
	id := "did:nuts:1#1"

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		var parsedURI ssi.URI
		ctx.didman.EXPECT().DeleteService(gomock.Any()).DoAndReturn(
			func(id interface{}) error {
				parsedURI = id.(ssi.URI)
				return nil
			})
		ctx.echo.EXPECT().NoContent(http.StatusNoContent).Return(nil)

		err := ctx.wrapper.DeleteService(ctx.echo, id)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, id, parsedURI.String())
	})

	t.Run("error - incorrect uri", func(t *testing.T) {
		ctx := newMockContext(t)
		err := ctx.wrapper.DeleteService(ctx.echo, ":")

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test.AssertErrProblemTitle(t, problemTitleDeleteService, err)
		test.AssertErrProblemDetail(t, "failed to parse URI: parse \":\": missing protocol scheme", err)
	})

	t.Run("error - DID not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().DeleteService(gomock.Any()).Return(types.ErrNotFound)

		err := ctx.wrapper.DeleteService(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusNotFound, err)
		test.AssertErrProblemTitle(t, problemTitleDeleteService, err)
	})

	t.Run("error - in use", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().DeleteService(gomock.Any()).Return(didman.ErrServiceInUse)

		err := ctx.wrapper.DeleteService(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusConflict, err)
		test.AssertErrProblemTitle(t, problemTitleDeleteService, err)
	})

	t.Run("error - deactivated", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().DeleteService(gomock.Any()).Return(types.ErrDeactivated)

		err := ctx.wrapper.DeleteService(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusConflict, err)
		test.AssertErrProblemDetail(t, types.ErrDeactivated.Error(), err)
		test.AssertErrProblemTitle(t, problemTitleDeleteService, err)
	})

	t.Run("error - not managed", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().DeleteService(gomock.Any()).Return(types.ErrDIDNotManagedByThisNode)

		err := ctx.wrapper.DeleteService(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test.AssertErrProblemDetail(t, types.ErrDIDNotManagedByThisNode.Error(), err)
		test.AssertErrProblemTitle(t, problemTitleDeleteService, err)
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().DeleteService(gomock.Any()).Return(errors.New("b00m!"))

		err := ctx.wrapper.DeleteService(ctx.echo, id)

		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusInternalServerError, err)
		test.AssertErrProblemTitle(t, problemTitleDeleteService, err)
	})
}

func TestWrapper_UpdateContactInformation(t *testing.T) {
	idStr := "did:nuts:1"
	id, _ := did.ParseDID(idStr)

	request := ContactInformation{
		Name:    "TestSoft NL",
		Email:   "nuts-node@example.com",
		Phone:   "0031611122235",
		Website: "www.example.com",
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*ContactInformation)
			*p = request
			return nil
		})

		ctx.didman.EXPECT().UpdateContactInformation(*id, request).Return(&request, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, &request)

		err := ctx.wrapper.UpdateContactInformation(ctx.echo, idStr)
		if !assert.NoError(t, err) {
			return
		}
	})

	t.Run("error - incorrect DID", func(t *testing.T) {
		invalidDIDStr := "nuts:123"
		ctx := newMockContext(t)
		err := ctx.wrapper.UpdateContactInformation(ctx.echo, invalidDIDStr)
		if !test.AssertErrIsProblem(t, err) {
			return
		}
		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test.AssertErrProblemTitle(t, problemTitleUpdateContactInformation, err)
		test.AssertErrProblemDetail(t, "failed to parse DID: input does not begin with 'did:' prefix", err)
	})

	t.Run("error - unknown DID", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*ContactInformation)
			*p = request
			return nil
		})

		ctx.didman.EXPECT().UpdateContactInformation(*id, request).Return(nil, types.ErrNotFound)

		err := ctx.wrapper.UpdateContactInformation(ctx.echo, idStr)
		if !test.AssertErrIsProblem(t, err) {
			return
		}

		test.AssertErrProblemStatusCode(t, http.StatusNotFound, err)
		test.AssertErrProblemTitle(t, problemTitleUpdateContactInformation, err)
		test.AssertErrProblemDetail(t, "unable to find the DID document", err)
	})
	t.Run("error - deactivated", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*ContactInformation)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().UpdateContactInformation(*id, request).Return(nil, types.ErrDeactivated)

		err := ctx.wrapper.UpdateContactInformation(ctx.echo, idStr)
		if !test.AssertErrIsProblem(t, err) {
			return
		}

		test.AssertErrProblemStatusCode(t, http.StatusConflict, err)
		test.AssertErrProblemTitle(t, problemTitleUpdateContactInformation, err)
		test.AssertErrProblemDetail(t, "the DID document has been deactivated", err)
	})

	t.Run("error - not managed", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*ContactInformation)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().UpdateContactInformation(*id, request).Return(nil, types.ErrDIDNotManagedByThisNode)

		err := ctx.wrapper.UpdateContactInformation(ctx.echo, idStr)
		if !test.AssertErrIsProblem(t, err) {
			return
		}

		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test.AssertErrProblemTitle(t, problemTitleUpdateContactInformation, err)
		test.AssertErrProblemDetail(t, "DID document not managed by this node", err)
	})
	t.Run("error - other problem", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*ContactInformation)
			*p = request
			return nil
		})

		ctx.didman.EXPECT().UpdateContactInformation(*id, request).Return(nil, fmt.Errorf("other problem"))

		err := ctx.wrapper.UpdateContactInformation(ctx.echo, idStr)
		if !test.AssertErrIsProblem(t, err) {
			return
		}

		test.AssertErrProblemStatusCode(t, http.StatusInternalServerError, err)
		test.AssertErrProblemTitle(t, problemTitleUpdateContactInformation, err)
		test.AssertErrProblemDetail(t, "other problem", err)
	})
}

func TestWrapper_GetContactInformation(t *testing.T) {
	idStr := "did:nuts:1"
	id, _ := did.ParseDID(idStr)

	contactInformation := ContactInformation{
		Name:    "TestSoft NL",
		Email:   "nuts-node@example.com",
		Phone:   "0031611122235",
		Website: "www.example.com",
	}
	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().GetContactInformation(*id).Return(&contactInformation, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, &contactInformation)
		err := ctx.wrapper.GetContactInformation(ctx.echo, idStr)
		assert.NoError(t, err)
	})

	t.Run("error - invalid DID", func(t *testing.T) {
		invalidDIDStr := "nuts:123"
		ctx := newMockContext(t)
		err := ctx.wrapper.GetContactInformation(ctx.echo, invalidDIDStr)
		if !test.AssertErrIsProblem(t, err) {
			return
		}

		test.AssertErrProblemStatusCode(t, http.StatusBadRequest, err)
		test.AssertErrProblemTitle(t, problemTitleGetContactInformation, err)
		test.AssertErrProblemDetail(t, "failed to parse DID: input does not begin with 'did:' prefix", err)
	})
	t.Run("error - DID not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().GetContactInformation(*id).Return(nil, types.ErrNotFound)
		err := ctx.wrapper.GetContactInformation(ctx.echo, idStr)
		if !test.AssertErrIsProblem(t, err) {
			return
		}

		test.AssertErrProblemStatusCode(t, http.StatusNotFound, err)
		test.AssertErrProblemTitle(t, problemTitleGetContactInformation, err)
		test.AssertErrProblemDetail(t, "unable to find the DID document", err)
	})
	t.Run("error - contact information not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().GetContactInformation(*id).Return(nil, nil)
		err := ctx.wrapper.GetContactInformation(ctx.echo, idStr)
		if !test.AssertErrIsProblem(t, err) {
			return
		}

		test.AssertErrProblemStatusCode(t, http.StatusNotFound, err)
		test.AssertErrProblemTitle(t, problemTitleGetContactInformation, err)
		test.AssertErrProblemDetail(t, "contact information for DID not found", err)
	})
	t.Run("error - other error", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().GetContactInformation(*id).Return(nil, fmt.Errorf("other error"))
		err := ctx.wrapper.GetContactInformation(ctx.echo, idStr)
		if !test.AssertErrIsProblem(t, err) {
			return
		}

		test.AssertErrProblemStatusCode(t, http.StatusInternalServerError, err)
		test.AssertErrProblemTitle(t, problemTitleGetContactInformation, err)
		test.AssertErrProblemDetail(t, "other error", err)
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
