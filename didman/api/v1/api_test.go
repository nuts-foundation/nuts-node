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
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/vdr"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapper_Preprocess(t *testing.T) {
	w := &Wrapper{}
	echoCtx := echo.New().NewContext(&http.Request{}, nil)
	echoCtx.Set(core.UserContextKey, "user")

	w.Preprocess("foo", echoCtx)

	audit.AssertAuditInfo(t, echoCtx, "user@", "Didman", "foo")
	assert.Equal(t, "foo", echoCtx.Get(core.OperationIDContextKey))
	assert.Equal(t, "Didman", echoCtx.Get(core.ModuleNameContextKey))
	assert.Same(t, w, echoCtx.Get(core.StatusCodeResolverContextKey))
}

func TestWrapper_AddEndpoint(t *testing.T) {
	id := "did:nuts:1"
	request := EndpointProperties{
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
			p := f.(*EndpointProperties)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddEndpoint(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, id interface{}, t interface{}, u interface{}) (*did.Service, error) {
				parsedDID = id.(did.DID)
				parsedURL = u.(url.URL)
				parsedType = t.(string)
				return &did.Service{
					ID:              parsedDID.URI(),
					Type:            parsedType,
					ServiceEndpoint: parsedURL.String(),
				}, nil
			})
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).Return(nil)

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		require.Nil(t, err)
		assert.Equal(t, id, parsedDID.String())
		assert.Equal(t, request.Endpoint, parsedURL.String())
		assert.Equal(t, request.Type, parsedType)
	})

	t.Run("error - incorrect type", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointProperties)
			*p = EndpointProperties{Endpoint: "https://api.example.com/v1"}
			return nil
		})
		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		assert.Equal(t, err, core.InvalidInputError("invalid value for type"))
	})

	t.Run("error - incorrect endpoint", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointProperties)
			*p = EndpointProperties{Type: "type", Endpoint: ":"}
			return nil
		})
		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		assert.ErrorIs(t, err, core.InvalidInputError(""))
	})

	t.Run("error - incorrect did", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointProperties)
			*p = request
			return nil
		})
		err := ctx.wrapper.AddEndpoint(ctx.echo, "")

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.wrapper.ResolveStatusCode(err))
	})

	t.Run("error - AddEndpoint fails", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointProperties)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddEndpoint(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, types.ErrNotFound)

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		assert.ErrorIs(t, err, types.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, ctx.wrapper.ResolveStatusCode(err))
	})

	t.Run("error - incorrect post body", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		assert.ErrorIs(t, err, core.InvalidInputError(""))
	})

	t.Run("error - deactivated", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointProperties)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddEndpoint(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, types.ErrDeactivated)

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		assert.ErrorIs(t, err, types.ErrDeactivated)
		assert.Equal(t, http.StatusConflict, ctx.wrapper.ResolveStatusCode(err))
	})

	t.Run("error - not managed", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointProperties)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddEndpoint(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, types.ErrDIDNotManagedByThisNode)

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		assert.ErrorIs(t, err, types.ErrDIDNotManagedByThisNode)
		assert.Equal(t, http.StatusBadRequest, ctx.wrapper.ResolveStatusCode(err))
	})

	t.Run("error - duplicate", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointProperties)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddEndpoint(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, types.ErrDuplicateService)

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		assert.ErrorIs(t, err, types.ErrDuplicateService)
		assert.Equal(t, http.StatusConflict, ctx.wrapper.ResolveStatusCode(err))
	})

	t.Run("error - invalid service", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointProperties)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddEndpoint(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, vdr.InvalidServiceError{errors.New("custom error")})

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		assert.ErrorAs(t, err, new(vdr.InvalidServiceError))
		assert.Equal(t, http.StatusBadRequest, ctx.wrapper.ResolveStatusCode(err))
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*EndpointProperties)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddEndpoint(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("b00m!"))

		err := ctx.wrapper.AddEndpoint(ctx.echo, id)

		assert.EqualError(t, err, "b00m!")
	})
}

func TestWrapper_DeleteEndpointsByType(t *testing.T) {
	idStr := "did:nuts:123"
	parsedID, _ := did.ParseDID(idStr)
	endpointType := "eOverdracht"

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().DeleteEndpointsByType(audit.ContextWithAuditInfo(), *parsedID, endpointType)
		ctx.echo.EXPECT().NoContent(http.StatusNoContent)

		err := ctx.wrapper.DeleteEndpointsByType(ctx.echo, idStr, endpointType)

		require.Nil(t, err)
	})

	t.Run("error - invalid did", func(t *testing.T) {
		ctx := newMockContext(t)
		err := ctx.wrapper.DeleteEndpointsByType(ctx.echo, "not a did", endpointType)
		assert.ErrorIs(t, err, did.ErrInvalidDID)
	})

	t.Run("error - invalid type", func(t *testing.T) {
		ctx := newMockContext(t)
		err := ctx.wrapper.DeleteEndpointsByType(ctx.echo, idStr, "")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
	})

	t.Run("error - didman.DeleteEndpointsByType returns error", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().DeleteEndpointsByType(audit.ContextWithAuditInfo(), *parsedID, endpointType).Return(types.ErrNotFound)
		err := ctx.wrapper.DeleteEndpointsByType(ctx.echo, idStr, endpointType)
		assert.ErrorIs(t, err, types.ErrNotFound)
	})
}

func TestWrapper_AddCompoundService(t *testing.T) {
	id := "did:nuts:1"
	serviceEndpoint := map[string]interface{}{
		"foo": "did:nuts:12345/serviceEndpoint?type=foo",
		"bar": "did:nuts:54321/serviceEndpoint?type=bar",
	}
	request := CompoundServiceProperties{
		ServiceEndpoint: serviceEndpoint,
		Type:            "type",
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		var (
			parsedDID      did.DID
			parsedEndpoint map[string]ssi.URI
			parsedType     string
		)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*CompoundServiceProperties)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddCompoundService(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, subject interface{}, endpointType interface{}, endpoint interface{}) (*did.Service, error) {
				parsedDID = subject.(did.DID)
				parsedEndpoint = endpoint.(map[string]ssi.URI)
				parsedType = endpointType.(string)
				return &did.Service{
					ID:              parsedDID.URI(),
					Type:            parsedType,
					ServiceEndpoint: serviceEndpoint,
				}, nil
			})
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).Return(nil)

		err := ctx.wrapper.AddCompoundService(ctx.echo, id)

		require.NoError(t, err)
		assert.Equal(t, id, parsedDID.String())
		assert.Len(t, parsedEndpoint, 2)
		assert.Equal(t, request.ServiceEndpoint["foo"], parsedEndpoint["foo"].String())
		assert.Equal(t, request.ServiceEndpoint["bar"], parsedEndpoint["bar"].String())
		assert.Equal(t, request.Type, parsedType)
	})

	t.Run("error - didman.AddCompoundService fails", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*CompoundServiceProperties)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddCompoundService(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("failed"))

		err := ctx.wrapper.AddCompoundService(ctx.echo, id)

		assert.EqualError(t, err, "failed")
	})

	t.Run("error - incorrect endpoint (not a URI)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*CompoundServiceProperties)
			*p = CompoundServiceProperties{Type: "type", ServiceEndpoint: map[string]interface{}{"foo": ":"}}
			return nil
		})
		err := ctx.wrapper.AddCompoundService(ctx.echo, id)

		assert.EqualError(t, err, "invalid reference for service 'foo': parse \":\": missing protocol scheme")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
	})

	t.Run("error - incorrect endpoint (not a string)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*CompoundServiceProperties)
			*p = CompoundServiceProperties{Type: "type", ServiceEndpoint: map[string]interface{}{"foo": map[string]interface{}{}}}
			return nil
		})
		err := ctx.wrapper.AddCompoundService(ctx.echo, id)

		assert.EqualError(t, err, "invalid reference for service 'foo': not a string")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
	})

	t.Run("error - incorrect did", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*CompoundServiceProperties)
			*p = request
			return nil
		})
		err := ctx.wrapper.AddCompoundService(ctx.echo, "")

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.wrapper.ResolveStatusCode(err))
	})

	t.Run("error - incorrect type", func(t *testing.T) {
		ctx := newMockContext(t)
		request := CompoundServiceProperties{
			ServiceEndpoint: serviceEndpoint,
			Type:            "",
		}
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*CompoundServiceProperties)
			*p = request
			return nil
		})
		err := ctx.wrapper.AddCompoundService(ctx.echo, id)

		assert.Equal(t, err, core.InvalidInputError("invalid value for type"))
	})

	t.Run("error - invalid service", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*CompoundServiceProperties)
			*p = request
			return nil
		})
		ctx.didman.EXPECT().AddCompoundService(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, vdr.InvalidServiceError{errors.New("custom error")})

		err := ctx.wrapper.AddCompoundService(ctx.echo, id)

		assert.ErrorAs(t, err, new(vdr.InvalidServiceError))
		assert.Equal(t, http.StatusBadRequest, ctx.wrapper.ResolveStatusCode(err))
	})

	t.Run("error - incorrect post body", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))

		err := ctx.wrapper.AddCompoundService(ctx.echo, id)

		assert.EqualError(t, err, "failed to parse v1.CompoundServiceProperties: b00m!")
	})
}

func TestWrapper_GetCompoundServices(t *testing.T) {
	idStr := "did:nuts:1#1"
	id, _ := did.ParseDIDURL(idStr)
	cServices := []did.Service{{
		Type:            "eOverdracht",
		ServiceEndpoint: map[string]interface{}{"foo": "http://example.org"},
	}}
	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().GetCompoundServices(*id).Return(cServices, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, cServices)
		err := ctx.wrapper.GetCompoundServices(ctx.echo, idStr)
		assert.NoError(t, err)
	})
	t.Run("no results (nil maps to empty array)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().GetCompoundServices(*id).Return(nil, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, []did.Service{})
		err := ctx.wrapper.GetCompoundServices(ctx.echo, idStr)
		assert.NoError(t, err)
	})
	t.Run("error - invalid DID", func(t *testing.T) {
		invalidDIDStr := "nuts:123"
		ctx := newMockContext(t)
		err := ctx.wrapper.GetCompoundServices(ctx.echo, invalidDIDStr)

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.wrapper.ResolveStatusCode(err))
	})
	t.Run("error - DID not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().GetCompoundServices(*id).Return(nil, types.ErrNotFound)
		err := ctx.wrapper.GetCompoundServices(ctx.echo, idStr)

		assert.ErrorIs(t, err, types.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, ctx.wrapper.ResolveStatusCode(err))
	})
}

func TestWrapper_GetCompoundServiceEndpoint(t *testing.T) {
	idStr := "did:nuts:1"
	id, _ := did.ParseDIDURL(idStr)
	const expected = "result"
	expectedResult := EndpointResponse{Endpoint: expected}
	req := http.Request{Header: map[string][]string{}}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContextWithRequest(t, &req)
		ctx.didman.EXPECT().GetCompoundServiceEndpoint(*id, "csType", "eType", true).Return(expected, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, expectedResult)

		err := ctx.wrapper.GetCompoundServiceEndpoint(ctx.echo, idStr, "csType", "eType", GetCompoundServiceEndpointParams{})

		assert.NoError(t, err)
	})
	t.Run("ok as text/plain", func(t *testing.T) {
		req := http.Request{Header: map[string][]string{
			"Accept": {"text/plain"},
		}}
		ctx := newMockContextWithRequest(t, &req)

		ctx.didman.EXPECT().GetCompoundServiceEndpoint(*id, "csType", "eType", true).Return(expected, nil)
		ctx.echo.EXPECT().String(http.StatusOK, expected)
		err := ctx.wrapper.GetCompoundServiceEndpoint(ctx.echo, idStr, "csType", "eType", GetCompoundServiceEndpointParams{})

		assert.NoError(t, err)
	})
	t.Run("ok - no resolve", func(t *testing.T) {
		ctx := newMockContextWithRequest(t, &req)
		ctx.didman.EXPECT().GetCompoundServiceEndpoint(*id, "csType", "eType", false).Return(expected, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, expectedResult)
		f := false

		err := ctx.wrapper.GetCompoundServiceEndpoint(ctx.echo, idStr, "csType", "eType", GetCompoundServiceEndpointParams{Resolve: &f})

		assert.NoError(t, err)
	})
	t.Run("error - invalid DID", func(t *testing.T) {
		invalidDIDStr := "nuts:123"
		ctx := newMockContextWithRequest(t, &req)

		err := ctx.wrapper.GetCompoundServiceEndpoint(ctx.echo, invalidDIDStr, "", "", GetCompoundServiceEndpointParams{})

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.wrapper.ResolveStatusCode(err))
	})
	t.Run("error mapping", func(t *testing.T) {
		ctx := newMockContext(t)
		assert.Equal(t, http.StatusNotFound, ctx.wrapper.ResolveStatusCode(types.ErrServiceNotFound))
		assert.Equal(t, http.StatusBadRequest, ctx.wrapper.ResolveStatusCode(didservice.DIDServiceQueryError{errors.New("arbitrary")}))
		assert.Equal(t, http.StatusNotAcceptable, ctx.wrapper.ResolveStatusCode(types.ErrServiceReferenceToDeep))
		assert.Equal(t, http.StatusNotAcceptable, ctx.wrapper.ResolveStatusCode(didman.ErrReferencedServiceNotAnEndpoint{}))
		assert.Equal(t, http.StatusNotFound, ctx.wrapper.ResolveStatusCode(types.ErrNotFound))
	})
}

func TestWrapper_DeleteService(t *testing.T) {
	id := "did:nuts:1#1"

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		var parsedURI ssi.URI
		ctx.didman.EXPECT().DeleteService(audit.ContextWithAuditInfo(), gomock.Any()).DoAndReturn(
			func(_ context.Context, id interface{}) error {
				parsedURI = id.(ssi.URI)
				return nil
			})
		ctx.echo.EXPECT().NoContent(http.StatusNoContent).Return(nil)

		err := ctx.wrapper.DeleteService(ctx.echo, id)

		require.NoError(t, err)
		assert.Equal(t, id, parsedURI.String())
	})

	t.Run("error - incorrect uri", func(t *testing.T) {
		ctx := newMockContext(t)
		err := ctx.wrapper.DeleteService(ctx.echo, ":")

		assert.EqualError(t, err, "failed to parse URI: parse \":\": missing protocol scheme")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
	})

	t.Run("error - service fails", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().DeleteService(audit.ContextWithAuditInfo(), gomock.Any()).Return(types.ErrNotFound)

		err := ctx.wrapper.DeleteService(ctx.echo, id)

		assert.ErrorIs(t, err, types.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, ctx.wrapper.ResolveStatusCode(err))
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

		ctx.didman.EXPECT().UpdateContactInformation(audit.ContextWithAuditInfo(), *id, request).Return(&request, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, &request)

		err := ctx.wrapper.UpdateContactInformation(ctx.echo, idStr)
		require.NoError(t, err)
	})

	t.Run("error - incorrect DID", func(t *testing.T) {
		invalidDIDStr := "nuts:123"
		ctx := newMockContext(t)
		err := ctx.wrapper.UpdateContactInformation(ctx.echo, invalidDIDStr)

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.wrapper.ResolveStatusCode(err))
	})

	t.Run("error - service fails DID", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			p := f.(*ContactInformation)
			*p = request
			return nil
		})

		ctx.didman.EXPECT().UpdateContactInformation(audit.ContextWithAuditInfo(), *id, request).Return(nil, types.ErrNotFound)

		err := ctx.wrapper.UpdateContactInformation(ctx.echo, idStr)

		assert.ErrorIs(t, err, types.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, ctx.wrapper.ResolveStatusCode(err))
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

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, ctx.wrapper.ResolveStatusCode(err))
	})
	t.Run("error - service fails", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().GetContactInformation(*id).Return(nil, types.ErrNotFound)
		err := ctx.wrapper.GetContactInformation(ctx.echo, idStr)

		assert.ErrorIs(t, err, types.ErrNotFound)
	})
	t.Run("error - contact information not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().GetContactInformation(*id).Return(nil, nil)
		err := ctx.wrapper.GetContactInformation(ctx.echo, idStr)

		assert.EqualError(t, err, "contact information for DID not found")
		assert.ErrorIs(t, err, core.NotFoundError(""))
	})
}

func TestWrapper_SearchOrganizations(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		idStr := "did:nuts:1"
		id, _ := did.ParseDID(idStr)

		ctx := newMockContext(t)
		serviceType := "service"
		results := []OrganizationSearchResult{{DIDDocument: did.Document{ID: *id}, Organization: map[string]interface{}{"name": "bar"}}}
		ctx.didman.EXPECT().SearchOrganizations(gomock.Any(), "query", &serviceType).Return(results, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, results)

		err := ctx.wrapper.SearchOrganizations(ctx.echo, SearchOrganizationsParams{
			Query:          "query",
			DidServiceType: &serviceType,
		})

		assert.NoError(t, err)
	})
	t.Run("no results", func(t *testing.T) {
		ctx := newMockContext(t)
		serviceType := "service"
		ctx.didman.EXPECT().SearchOrganizations(gomock.Any(), "query", &serviceType).Return(nil, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, []OrganizationSearchResult{})

		err := ctx.wrapper.SearchOrganizations(ctx.echo, SearchOrganizationsParams{
			Query:          "query",
			DidServiceType: &serviceType,
		})

		assert.NoError(t, err)
	})
	t.Run("error - service fails", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didman.EXPECT().SearchOrganizations(gomock.Any(), "query", nil).Return(nil, types.ErrNotFound)
		err := ctx.wrapper.SearchOrganizations(ctx.echo, SearchOrganizationsParams{Query: "query"})

		assert.ErrorIs(t, err, types.ErrNotFound)
	})
}

type mockContext struct {
	ctrl       *gomock.Controller
	echo       *mock.MockContext
	didman     *didman.MockDidman
	wrapper    Wrapper
	requestCtx context.Context
}

func newMockContext(t *testing.T) mockContext {
	requestCtx := audit.TestContext()
	request, _ := http.NewRequestWithContext(requestCtx, "GET", "/", nil)
	return newMockContextWithRequest(t, request)
}

func newMockContextWithRequest(t *testing.T, request *http.Request) mockContext {
	ctrl := gomock.NewController(t)
	didmanMock := didman.NewMockDidman(ctrl)
	requestCtx := audit.TestContext()
	echoMock := mock.NewMockContext(ctrl)
	echoMock.EXPECT().Request().Return(request).AnyTimes()

	return mockContext{
		ctrl:       ctrl,
		echo:       echoMock,
		didman:     didmanMock,
		wrapper:    Wrapper{didmanMock},
		requestCtx: requestCtx,
	}
}
