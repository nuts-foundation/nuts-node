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
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/http"
	"net/url"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestWrapper_AddEndpoint(t *testing.T) {
	targetDID := did.MustParseDID("did:nuts:1")
	serviceID := ssi.MustParseURI(targetDID.String() + "#service")
	serviceEndpoint, _ := url.Parse("https://api.example.com/v1")
	service := EndpointProperties{
		Endpoint: serviceEndpoint.String(),
		Type:     "type",
	}
	request := AddEndpointRequestObject{
		Did:  targetDID.String(),
		Body: &service,
	}
	ctx := audit.TestContext()

	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().AddEndpoint(audit.ContextWithAuditInfo(), targetDID, service.Type, *serviceEndpoint).Return(&did.Service{
			ID:              serviceID,
			Type:            service.Type,
			ServiceEndpoint: service.Endpoint,
		}, nil)

		response, err := test.wrapper.AddEndpoint(ctx, request)

		assert.Nil(t, err)
		assert.NotNil(t, response)
	})

	t.Run("error - incorrect type", func(t *testing.T) {
		test := newMockContext(t)
		response, err := test.wrapper.AddEndpoint(ctx, AddEndpointRequestObject{
			Did: targetDID.String(),
			Body: &EndpointProperties{
				Endpoint: serviceEndpoint.String(),
			},
		})

		assert.Equal(t, err, core.InvalidInputError("invalid value for type"))
		assert.Nil(t, response)
	})

	t.Run("error - incorrect endpoint", func(t *testing.T) {
		test := newMockContext(t)
		response, err := test.wrapper.AddEndpoint(ctx, AddEndpointRequestObject{
			Did: targetDID.String(),
			Body: &EndpointProperties{
				Type:     service.Type,
				Endpoint: ":",
			},
		})

		assert.ErrorIs(t, err, core.InvalidInputError(""))
		assert.Nil(t, response)
	})

	t.Run("error - incorrect did", func(t *testing.T) {
		test := newMockContext(t)
		response, err := test.wrapper.AddEndpoint(ctx, AddEndpointRequestObject{
			Body: &EndpointProperties{
				Type:     service.Type,
				Endpoint: serviceEndpoint.String(),
			},
		})

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - AddEndpoint fails", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().AddEndpoint(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, resolver.ErrNotFound)

		response, err := test.wrapper.AddEndpoint(ctx, request)

		assert.ErrorIs(t, err, resolver.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - deactivated", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().AddEndpoint(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, resolver.ErrDeactivated)

		response, err := test.wrapper.AddEndpoint(ctx, request)

		assert.ErrorIs(t, err, resolver.ErrDeactivated)
		assert.Equal(t, http.StatusConflict, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - not managed", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().AddEndpoint(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, resolver.ErrDIDNotManagedByThisNode)

		response, err := test.wrapper.AddEndpoint(ctx, request)

		assert.ErrorIs(t, err, resolver.ErrDIDNotManagedByThisNode)
		assert.Equal(t, http.StatusBadRequest, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - duplicate", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().AddEndpoint(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, resolver.ErrDuplicateService)

		response, err := test.wrapper.AddEndpoint(ctx, request)

		assert.ErrorIs(t, err, resolver.ErrDuplicateService)
		assert.Equal(t, http.StatusConflict, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - invalid service", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().AddEndpoint(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, didnuts.InvalidServiceError{errors.New("custom error")})

		response, err := test.wrapper.AddEndpoint(ctx, request)

		assert.ErrorAs(t, err, new(didnuts.InvalidServiceError))
		assert.Equal(t, http.StatusBadRequest, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - other", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().AddEndpoint(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("b00m!"))

		response, err := test.wrapper.AddEndpoint(ctx, request)

		assert.EqualError(t, err, "b00m!")
		assert.Nil(t, response)
	})
}

func TestWrapper_UpdateEndpoint(t *testing.T) {
	targetDID := did.MustParseDID("did:nuts:1")
	serviceID := ssi.MustParseURI(targetDID.String() + "#service")
	serviceEndpoint, _ := url.Parse("https://api.example.com/v1")
	ctx := audit.TestContext()

	t.Run("ok - type not set", func(t *testing.T) {
		service := EndpointProperties{
			Endpoint: serviceEndpoint.String(),
		}
		request := UpdateEndpointRequestObject{
			Did:  targetDID.String(),
			Type: "type",
			Body: &service,
		}
		test := newMockContext(t)
		test.didman.EXPECT().UpdateEndpoint(audit.ContextWithAuditInfo(), targetDID, request.Type, *serviceEndpoint).Return(&did.Service{
			ID:              serviceID,
			Type:            request.Type,
			ServiceEndpoint: service.Endpoint,
		}, nil)

		response, err := test.wrapper.UpdateEndpoint(ctx, request)

		assert.Nil(t, err)
		assert.NotNil(t, response)
	})
	t.Run("ok - type set", func(t *testing.T) {
		service := EndpointProperties{
			Endpoint: serviceEndpoint.String(),
			Type:     "type",
		}
		request := UpdateEndpointRequestObject{
			Did:  targetDID.String(),
			Type: "type",
			Body: &service,
		}
		test := newMockContext(t)
		test.didman.EXPECT().UpdateEndpoint(audit.ContextWithAuditInfo(), targetDID, request.Type, *serviceEndpoint).Return(&did.Service{
			ID:              serviceID,
			Type:            request.Type,
			ServiceEndpoint: service.Endpoint,
		}, nil)

		response, err := test.wrapper.UpdateEndpoint(ctx, request)

		assert.Nil(t, err)
		assert.NotNil(t, response)
	})
	t.Run("error - type set, but differs (updating not supported)", func(t *testing.T) {
		service := EndpointProperties{
			Endpoint: serviceEndpoint.String(),
			Type:     "type",
		}
		request := UpdateEndpointRequestObject{
			Did:  targetDID.String(),
			Type: "type-different",
			Body: &service,
		}
		test := newMockContext(t)

		_, err := test.wrapper.UpdateEndpoint(ctx, request)

		assert.EqualError(t, err, "updating endpoint type is not supported")
	})
}

func TestWrapper_DeleteEndpointsByType(t *testing.T) {
	idStr := "did:nuts:123"
	parsedID, _ := did.ParseDID(idStr)
	endpointType := "eOverdracht"
	ctx := audit.TestContext()
	request := DeleteEndpointsByTypeRequestObject{
		Did:  parsedID.String(),
		Type: endpointType,
	}

	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().DeleteEndpointsByType(audit.ContextWithAuditInfo(), *parsedID, endpointType)

		response, err := test.wrapper.DeleteEndpointsByType(ctx, request)

		assert.Nil(t, err)
		assert.IsType(t, DeleteEndpointsByType204Response{}, response)
	})

	t.Run("error - invalid did", func(t *testing.T) {
		test := newMockContext(t)
		response, err := test.wrapper.DeleteEndpointsByType(ctx, DeleteEndpointsByTypeRequestObject{
			Did: "not a did",
		})
		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Nil(t, response)
	})

	t.Run("error - invalid type", func(t *testing.T) {
		test := newMockContext(t)
		response, err := test.wrapper.DeleteEndpointsByType(ctx, DeleteEndpointsByTypeRequestObject{
			Did:  parsedID.String(),
			Type: "",
		})
		assert.ErrorIs(t, err, core.InvalidInputError(""))
		assert.Nil(t, response)
	})

	t.Run("error - didman.DeleteEndpointsByType returns error", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().DeleteEndpointsByType(audit.ContextWithAuditInfo(), *parsedID, endpointType).Return(resolver.ErrNotFound)
		response, err := test.wrapper.DeleteEndpointsByType(ctx, request)
		assert.ErrorIs(t, err, resolver.ErrNotFound)
		assert.Nil(t, response)
	})
}

func TestWrapper_AddCompoundService(t *testing.T) {
	targetDID := did.MustParseDID("did:nuts:1")
	serviceEndpoint := map[string]ssi.URI{
		"foo": ssi.MustParseURI("did:nuts:12345/serviceEndpoint?type=foo"),
		"bar": ssi.MustParseURI("did:nuts:54321/serviceEndpoint?type=bar"),
	}
	service := CompoundServiceProperties{
		ServiceEndpoint: map[string]interface{}{},
		Type:            "type",
	}
	for key, val := range serviceEndpoint {
		service.ServiceEndpoint[key] = val.String()
	}
	request := AddCompoundServiceRequestObject{
		Did:  targetDID.String(),
		Body: &service,
	}
	result := &did.Service{
		ID:              ssi.MustParseURI(targetDID.String() + "#service"),
		Type:            service.Type,
		ServiceEndpoint: serviceEndpoint,
	}
	ctx := audit.TestContext()

	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().AddCompoundService(audit.ContextWithAuditInfo(), targetDID, service.Type, serviceEndpoint).Return(result, nil)

		response, err := test.wrapper.AddCompoundService(ctx, request)

		assert.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("error - didman.AddCompoundService fails", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().AddCompoundService(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("failed"))

		response, err := test.wrapper.AddCompoundService(ctx, request)

		assert.EqualError(t, err, "failed")
		assert.Nil(t, response)
	})

	t.Run("error - incorrect endpoint (not a URI)", func(t *testing.T) {
		test := newMockContext(t)

		response, err := test.wrapper.AddCompoundService(ctx, AddCompoundServiceRequestObject{
			Did:  targetDID.String(),
			Body: &CompoundServiceProperties{Type: "type", ServiceEndpoint: map[string]interface{}{"foo": ":"}},
		})

		assert.EqualError(t, err, "invalid reference for service 'foo': parse \":\": missing protocol scheme")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
		assert.Nil(t, response)
	})

	t.Run("error - incorrect endpoint (not a string)", func(t *testing.T) {
		test := newMockContext(t)
		response, err := test.wrapper.AddCompoundService(ctx, AddCompoundServiceRequestObject{
			Did: targetDID.String(),
			Body: &CompoundServiceProperties{
				Type:            "type",
				ServiceEndpoint: map[string]interface{}{"foo": map[string]interface{}{}},
			},
		})

		assert.EqualError(t, err, "invalid reference for service 'foo': not a string")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
		assert.Nil(t, response)
	})

	t.Run("error - incorrect did", func(t *testing.T) {
		test := newMockContext(t)
		response, err := test.wrapper.AddCompoundService(ctx, AddCompoundServiceRequestObject{Did: "not a did", Body: &CompoundServiceProperties{}})

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - incorrect type", func(t *testing.T) {
		test := newMockContext(t)

		response, err := test.wrapper.AddCompoundService(ctx, AddCompoundServiceRequestObject{
			Did: targetDID.String(),
			Body: &CompoundServiceProperties{
				Type: "",
			},
		})

		assert.Equal(t, err, core.InvalidInputError("invalid value for type"))
		assert.Nil(t, response)
	})

	t.Run("error - invalid service", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().AddCompoundService(audit.ContextWithAuditInfo(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, didnuts.InvalidServiceError{errors.New("custom error")})

		response, err := test.wrapper.AddCompoundService(ctx, request)

		assert.ErrorAs(t, err, new(didnuts.InvalidServiceError))
		assert.Equal(t, http.StatusBadRequest, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})
}

func TestWrapper_GetCompoundServices(t *testing.T) {
	targetDID := did.MustParseDID("did:nuts:1")
	request := GetCompoundServicesRequestObject{
		Did: targetDID.String(),
	}
	cServices := []did.Service{{
		Type:            "eOverdracht",
		ServiceEndpoint: map[string]interface{}{"foo": "http://example.org"},
	}}
	ctx := audit.TestContext()
	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().GetCompoundServices(targetDID).Return(cServices, nil)
		response, err := test.wrapper.GetCompoundServices(ctx, request)
		assert.NoError(t, err)
		assert.NotNil(t, response)
	})
	t.Run("no results (nil maps to empty array)", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().GetCompoundServices(targetDID).Return(nil, nil)
		response, err := test.wrapper.GetCompoundServices(ctx, request)
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Empty(t, response)
	})
	t.Run("error - invalid DID", func(t *testing.T) {
		invalidDIDStr := "nuts:123"
		test := newMockContext(t)
		response, err := test.wrapper.GetCompoundServices(ctx, GetCompoundServicesRequestObject{Did: invalidDIDStr})

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})
	t.Run("error - DID not found", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().GetCompoundServices(targetDID).Return(nil, resolver.ErrNotFound)
		response, err := test.wrapper.GetCompoundServices(ctx, request)

		assert.ErrorIs(t, err, resolver.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})
}

func TestWrapper_GetCompoundServiceEndpoint(t *testing.T) {
	targetDID := did.MustParseDID("did:nuts:1")
	request := GetCompoundServiceEndpointRequestObject{
		Did:                 targetDID.String(),
		CompoundServiceType: "csType",
		EndpointType:        "eType",
		Params:              GetCompoundServiceEndpointParams{},
	}
	const expected = "result"
	ctx := audit.TestContext()

	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().GetCompoundServiceEndpoint(targetDID, request.CompoundServiceType, request.EndpointType, true).Return(expected, nil)

		response, err := test.wrapper.GetCompoundServiceEndpoint(ctx, request)

		assert.NoError(t, err)
		assert.NotNil(t, response)
	})
	t.Run("ok as text/plain", func(t *testing.T) {
		test := newMockContext(t)

		requestCopy := request
		requestCopy.Params.Accept = new(string)
		*requestCopy.Params.Accept = "text/plain"
		test.didman.EXPECT().GetCompoundServiceEndpoint(targetDID, request.CompoundServiceType, request.EndpointType, true).Return(expected, nil)
		response, err := test.wrapper.GetCompoundServiceEndpoint(ctx, requestCopy)

		assert.NoError(t, err)
		assert.Equal(t, GetCompoundServiceEndpoint200TextResponse("result"), response)
	})
	t.Run("ok - no resolve", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().GetCompoundServiceEndpoint(targetDID, request.CompoundServiceType, request.EndpointType, false).Return(expected, nil)

		requestCopy := request
		requestCopy.Params.Resolve = new(bool)
		response, err := test.wrapper.GetCompoundServiceEndpoint(ctx, requestCopy)

		assert.NoError(t, err)
		assert.NotNil(t, response)
	})
	t.Run("error - invalid DID", func(t *testing.T) {
		test := newMockContext(t)

		requestCopy := request
		requestCopy.Did = "nuts:123"
		response, err := test.wrapper.GetCompoundServiceEndpoint(ctx, requestCopy)

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})
	t.Run("error mapping", func(t *testing.T) {
		ctx := newMockContext(t)
		assert.Equal(t, http.StatusNotFound, ctx.wrapper.ResolveStatusCode(resolver.ErrServiceNotFound))
		assert.Equal(t, http.StatusBadRequest, ctx.wrapper.ResolveStatusCode(resolver.ServiceQueryError{errors.New("arbitrary")}))
		assert.Equal(t, http.StatusNotAcceptable, ctx.wrapper.ResolveStatusCode(resolver.ErrServiceReferenceToDeep))
		assert.Equal(t, http.StatusNotAcceptable, ctx.wrapper.ResolveStatusCode(didman.ErrReferencedServiceNotAnEndpoint{}))
		assert.Equal(t, http.StatusNotFound, ctx.wrapper.ResolveStatusCode(resolver.ErrNotFound))
	})
}

func TestWrapper_DeleteService(t *testing.T) {
	id := ssi.MustParseURI("did:nuts:1#1")
	request := DeleteServiceRequestObject{
		Id: id.String(),
	}
	ctx := audit.TestContext()

	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().DeleteService(audit.ContextWithAuditInfo(), gomock.Any()).Return(nil)
		response, err := test.wrapper.DeleteService(ctx, request)

		require.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("error - incorrect uri", func(t *testing.T) {
		test := newMockContext(t)
		response, err := test.wrapper.DeleteService(ctx, DeleteServiceRequestObject{
			Id: ":",
		})

		assert.EqualError(t, err, "failed to parse URI: parse \":\": missing protocol scheme")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
		assert.Nil(t, response)
	})

	t.Run("error - service fails", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().DeleteService(audit.ContextWithAuditInfo(), gomock.Any()).Return(resolver.ErrNotFound)

		response, err := test.wrapper.DeleteService(ctx, request)

		assert.ErrorIs(t, err, resolver.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})
}

func TestWrapper_UpdateContactInformation(t *testing.T) {
	targetDID := did.MustParseDID("did:nuts:1")
	info := ContactInformation{
		Name:    "TestSoft NL",
		Email:   "nuts-node@example.com",
		Phone:   "0031611122235",
		Website: "www.example.com",
	}
	request := UpdateContactInformationRequestObject{
		Did:  targetDID.String(),
		Body: &info,
	}
	ctx := audit.TestContext()

	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().UpdateContactInformation(audit.ContextWithAuditInfo(), targetDID, info).Return(&info, nil)

		response, err := test.wrapper.UpdateContactInformation(ctx, request)
		require.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("error - incorrect DID", func(t *testing.T) {
		test := newMockContext(t)
		response, err := test.wrapper.UpdateContactInformation(ctx, UpdateContactInformationRequestObject{Did: "nuts:123"})

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})

	t.Run("error - service fails DID", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().UpdateContactInformation(audit.ContextWithAuditInfo(), targetDID, info).Return(nil, resolver.ErrNotFound)

		response, err := test.wrapper.UpdateContactInformation(ctx, request)

		assert.ErrorIs(t, err, resolver.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})
}

func TestWrapper_GetContactInformation(t *testing.T) {
	targetDID := did.MustParseDID("did:nuts:1")
	info := ContactInformation{
		Name:    "TestSoft NL",
		Email:   "nuts-node@example.com",
		Phone:   "0031611122235",
		Website: "www.example.com",
	}
	request := GetContactInformationRequestObject{
		Did: targetDID.String(),
	}
	ctx := audit.TestContext()
	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().GetContactInformation(targetDID).Return(&info, nil)
		response, err := test.wrapper.GetContactInformation(ctx, request)
		assert.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("error - invalid DID", func(t *testing.T) {
		test := newMockContext(t)
		response, err := test.wrapper.GetContactInformation(ctx, GetContactInformationRequestObject{Did: "nuts:123"})

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Equal(t, http.StatusBadRequest, test.wrapper.ResolveStatusCode(err))
		assert.Nil(t, response)
	})
	t.Run("error - service fails", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().GetContactInformation(targetDID).Return(nil, resolver.ErrNotFound)
		response, err := test.wrapper.GetContactInformation(ctx, request)

		assert.ErrorIs(t, err, resolver.ErrNotFound)
		assert.Nil(t, response)
	})
	t.Run("error - contact information not found", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().GetContactInformation(targetDID).Return(nil, nil)
		response, err := test.wrapper.GetContactInformation(ctx, request)

		assert.EqualError(t, err, "contact information for DID not found")
		assert.ErrorIs(t, err, core.NotFoundError(""))
		assert.Nil(t, response)
	})
}

func TestWrapper_SearchOrganizations(t *testing.T) {
	ctx := audit.TestContext()
	t.Run("ok", func(t *testing.T) {
		targetDID := did.MustParseDID("did:nuts:1")
		test := newMockContext(t)
		serviceType := "service"
		results := []OrganizationSearchResult{{DIDDocument: did.Document{ID: targetDID}, Organization: map[string]interface{}{"name": "bar"}}}
		test.didman.EXPECT().SearchOrganizations(gomock.Any(), "query", &serviceType).Return(results, nil)

		response, err := test.wrapper.SearchOrganizations(ctx, SearchOrganizationsRequestObject{
			Params: SearchOrganizationsParams{
				Query:          "query",
				DidServiceType: &serviceType,
			},
		})

		assert.NoError(t, err)
		assert.NotNil(t, response)
	})
	t.Run("no results", func(t *testing.T) {
		test := newMockContext(t)
		serviceType := "service"
		test.didman.EXPECT().SearchOrganizations(gomock.Any(), "query", &serviceType).Return(nil, nil)

		response, err := test.wrapper.SearchOrganizations(ctx, SearchOrganizationsRequestObject{
			Params: SearchOrganizationsParams{
				Query:          "query",
				DidServiceType: &serviceType,
			},
		})

		assert.NoError(t, err)
		assert.Empty(t, response)
	})
	t.Run("error - service fails", func(t *testing.T) {
		test := newMockContext(t)
		test.didman.EXPECT().SearchOrganizations(gomock.Any(), "query", nil).Return(nil, resolver.ErrNotFound)
		response, err := test.wrapper.SearchOrganizations(ctx, SearchOrganizationsRequestObject{
			Params: SearchOrganizationsParams{
				Query: "query",
			},
		})

		assert.ErrorIs(t, err, resolver.ErrNotFound)
		assert.Nil(t, response)
	})
}

type mockContext struct {
	ctrl    *gomock.Controller
	didman  *didman.MockDidman
	wrapper Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	didmanMock := didman.NewMockDidman(ctrl)
	return mockContext{
		ctrl:    ctrl,
		didman:  didmanMock,
		wrapper: Wrapper{didmanMock},
	}
}

func TestWrapper_UpdateCompoundService(t *testing.T) {
	targetDID := did.MustParseDID("did:nuts:1")
	serviceID := ssi.MustParseURI(targetDID.String() + "#service")
	serviceEndpoint := map[string]interface{}{
		"foo": "bar",
	}
	ctx := audit.TestContext()

	t.Run("ok - type not set", func(t *testing.T) {
		service := CompoundServiceProperties{
			ServiceEndpoint: serviceEndpoint,
		}
		request := UpdateCompoundServiceRequestObject{
			Did:  targetDID.String(),
			Type: "type",
			Body: &service,
		}
		test := newMockContext(t)
		test.didman.EXPECT().UpdateCompoundService(audit.ContextWithAuditInfo(), targetDID, request.Type, gomock.Any()).Return(&did.Service{
			ID:              serviceID,
			Type:            request.Type,
			ServiceEndpoint: serviceEndpoint,
		}, nil)

		response, err := test.wrapper.UpdateCompoundService(ctx, request)

		assert.Nil(t, err)
		assert.NotNil(t, response)
	})
	t.Run("ok - type set", func(t *testing.T) {
		service := CompoundServiceProperties{
			Type:            "type",
			ServiceEndpoint: serviceEndpoint,
		}
		request := UpdateCompoundServiceRequestObject{
			Did:  targetDID.String(),
			Type: "type",
			Body: &service,
		}
		test := newMockContext(t)
		test.didman.EXPECT().UpdateCompoundService(audit.ContextWithAuditInfo(), targetDID, request.Type, gomock.Any()).Return(&did.Service{
			ID:              serviceID,
			Type:            request.Type,
			ServiceEndpoint: serviceEndpoint,
		}, nil)

		response, err := test.wrapper.UpdateCompoundService(ctx, request)

		assert.Nil(t, err)
		assert.NotNil(t, response)
	})
	t.Run("error - type set, but differs (updating not supported)", func(t *testing.T) {
		service := CompoundServiceProperties{
			Type:            "type",
			ServiceEndpoint: serviceEndpoint,
		}
		request := UpdateCompoundServiceRequestObject{
			Did:  targetDID.String(),
			Type: "type-different",
			Body: &service,
		}
		test := newMockContext(t)

		_, err := test.wrapper.UpdateCompoundService(ctx, request)

		assert.EqualError(t, err, "updating compound service type is not supported")
	})
}
