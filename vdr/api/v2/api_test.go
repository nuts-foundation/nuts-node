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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"net/http"
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var id = did.MustParseDID("did:web:example.com:iam:1")

var didDoc = did.Document{
	ID: id,
}

func TestWrapper_CreateDID(t *testing.T) {
	t.Run("ok - defaults", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().Create(gomock.Any(), didsubject.DefaultCreationOptions()).Return([]did.Document{didDoc}, "subject", nil)

		response, err := ctx.client.CreateDID(nil, CreateDIDRequestObject{Body: &CreateDIDJSONRequestBody{}})

		require.NoError(t, err)
		assert.Len(t, response.(CreateDID200JSONResponse).Documents, 1)
		assert.Equal(t, "subject", response.(CreateDID200JSONResponse).Subject)
	})
	t.Run("with Subject", func(t *testing.T) {
		ctx := newMockContext(t)
		subject := "subject"
		ctx.subjectManager.EXPECT().Create(gomock.Any(), didsubject.DefaultCreationOptions().With(didsubject.SubjectCreationOption{Subject: subject})).Return([]did.Document{didDoc}, "subject", nil)

		response, err := ctx.client.CreateDID(nil, CreateDIDRequestObject{
			Body: &CreateDIDJSONRequestBody{
				Subject: &subject,
			},
		})

		require.NoError(t, err)
		assert.Len(t, response.(CreateDID200JSONResponse).Documents, 1)
		assert.Equal(t, "subject", response.(CreateDID200JSONResponse).Subject)
	})
	t.Run("error - create fails", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, "", assert.AnError)

		response, err := ctx.client.CreateDID(nil, CreateDIDRequestObject{
			Body: &CreateDIDJSONRequestBody{},
		})

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestWrapper_Deactivate(t *testing.T) {
	t.Run("ok - defaults", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().Deactivate(gomock.Any(), "subject").Return(nil)

		_, err := ctx.client.Deactivate(nil, DeactivateRequestObject{Id: "subject"})

		require.NoError(t, err)
	})
	t.Run("error", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().Deactivate(gomock.Any(), "subject").Return(assert.AnError)

		_, err := ctx.client.Deactivate(nil, DeactivateRequestObject{Id: "subject"})

		assert.Error(t, err)
	})
}

func TestWrapper_CreateService(t *testing.T) {
	service := did.Service{
		Type:            "api",
		ServiceEndpoint: "https://example.com",
	}
	t.Run("ok - defaults", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().CreateService(gomock.Any(), "subject", gomock.Any()).Return([]Service{service}, nil)

		response, err := ctx.client.CreateService(nil, CreateServiceRequestObject{
			Id:   "subject",
			Body: &service,
		})

		require.NoError(t, err)
		require.Len(t, response.(CreateService200JSONResponse), 1)
	})

	t.Run("error - create fails", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().CreateService(gomock.Any(), "subject", gomock.Any()).Return(nil, assert.AnError)

		response, err := ctx.client.CreateService(nil, CreateServiceRequestObject{
			Id:   "subject",
			Body: &service,
		})

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestWrapper_DeleteService(t *testing.T) {
	t.Run("ok - defaults", func(t *testing.T) {
		serviceID := ssi.MustParseURI("api")
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().DeleteService(gomock.Any(), "subject", serviceID).Return(nil)

		response, err := ctx.client.DeleteService(nil, DeleteServiceRequestObject{
			Id:        "subject",
			ServiceId: serviceID.String(),
		})

		require.NoError(t, err)
		assert.IsType(t, DeleteService204Response{}, response)
	})

	t.Run("error - delete fails", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().DeleteService(gomock.Any(), "subject", gomock.Any()).Return(assert.AnError)

		response, err := ctx.client.DeleteService(nil, DeleteServiceRequestObject{
			Id:        "subject",
			ServiceId: "1",
		})

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestWrapper_UpdateService(t *testing.T) {
	service := did.Service{
		Type:            "api",
		ServiceEndpoint: "https://example.com",
	}
	updatedService := service
	updatedService.ID = ssi.MustParseURI("1")
	t.Run("ok - defaults", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().UpdateService(gomock.Any(), "subject", updatedService.ID, service).Return([]Service{updatedService}, nil)

		response, err := ctx.client.UpdateService(nil, UpdateServiceRequestObject{
			Id:        "subject",
			ServiceId: "1",
			Body:      &service,
		})

		require.NoError(t, err)
		require.Len(t, response.(UpdateService200JSONResponse), 1)
	})
	t.Run("error - update fails", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().UpdateService(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, assert.AnError)

		response, err := ctx.client.UpdateService(nil, UpdateServiceRequestObject{
			Id:        "subject",
			ServiceId: "1",
			Body:      &service,
		})

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestWrapper_ListDIDs(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.documentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{did.MustParseDID("did:web:example.com:iam:1")}, nil)

		response, err := ctx.client.ListDIDs(context.Background(), ListDIDsRequestObject{})

		require.NoError(t, err)
		assert.Len(t, response.(ListDIDs200JSONResponse), 1)
	})

	t.Run("error - list fails", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.documentOwner.EXPECT().ListOwned(gomock.Any()).Return(nil, assert.AnError)

		response, err := ctx.client.ListDIDs(context.Background(), ListDIDsRequestObject{})

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestWrapper_SubjectDIDs(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().List(gomock.Any(), "subject").Return([]did.DID{did.MustParseDID("did:web:example.com:iam:1")}, nil)

		response, err := ctx.client.SubjectDIDs(context.Background(), SubjectDIDsRequestObject{Id: "subject"})

		require.NoError(t, err)
		assert.Len(t, response.(SubjectDIDs200JSONResponse), 1)
	})

	t.Run("error - list fails", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().List(gomock.Any(), "subject").Return(nil, assert.AnError)

		response, err := ctx.client.SubjectDIDs(context.Background(), SubjectDIDsRequestObject{Id: "subject"})

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestWrapper_ResolveDID(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		id := did.MustParseDID("did:web:example.com:iam:1")
		didDoc := &did.Document{
			ID: id,
		}
		ctx.didResolver.EXPECT().Resolve(id, nil).Return(didDoc, &resolver.DocumentMetadata{}, nil)

		response, err := ctx.client.ResolveDID(nil, ResolveDIDRequestObject{Did: id.String()})

		require.NoError(t, err)
		assert.Equal(t, id, response.(ResolveDID200JSONResponse).Document.ID)
	})
	t.Run("invalid DID", func(t *testing.T) {
		ctx := newMockContext(t)
		response, err := ctx.client.ResolveDID(nil, ResolveDIDRequestObject{Did: "invalid"})

		assert.ErrorIs(t, err, did.ErrInvalidDID)
		assert.Nil(t, response)
	})
	t.Run("resolver error", func(t *testing.T) {
		ctx := newMockContext(t)
		id := did.MustParseDID("did:web:example.com:iam:1")
		ctx.didResolver.EXPECT().Resolve(id, nil).Return(nil, nil, assert.AnError)

		response, err := ctx.client.ResolveDID(nil, ResolveDIDRequestObject{Did: id.String()})

		assert.ErrorIs(t, err, assert.AnError)
		assert.Nil(t, response)
	})
}

func TestWrapper_FindServices(t *testing.T) {
	stringService := did.Service{
		Type:            "string-api",
		ServiceEndpoint: "https://example.com",
	}
	objectService := did.Service{
		Type: "object-api",
		ServiceEndpoint: map[string]interface{}{
			"rest": "https://example.com/rest",
		},
	}
	stringArrayService := did.Service{
		Type:            "string-array-api",
		ServiceEndpoint: []interface{}{"https://example.com/rest1", "https://example.com/rest2"},
	}
	objectArrayService := did.Service{
		Type: "object-array-api",
		ServiceEndpoint: []interface{}{
			map[string]interface{}{"obj1": "https://example.com/rest1"},
			map[string]interface{}{"obj2": "https://example.com/rest2"},
		},
	}
	document := &did.Document{
		ID:      id,
		Service: []Service{stringService, objectService, stringArrayService, objectArrayService},
	}
	// remarshal DID document to make sure we don't have passing tests due to the way we construct the DID document above
	documentData, _ := document.MarshalJSON()
	document, err := did.ParseDocument(string(documentData))
	require.NoError(t, err)

	t.Run("no filter returns all services", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().FindServices(nil, "subject", nil).Return(document.Service, nil)

		response, err := ctx.client.FindServices(nil, FindServicesRequestObject{
			Id: "subject",
		})

		require.NoError(t, err)
		require.IsType(t, FindServices200JSONResponse{}, response)
		require.Len(t, response.(FindServices200JSONResponse), 4)
		assert.Contains(t, response.(FindServices200JSONResponse), stringService)
		assert.Contains(t, response.(FindServices200JSONResponse), objectService)
		assert.Contains(t, response.(FindServices200JSONResponse), stringArrayService)
		assert.Contains(t, response.(FindServices200JSONResponse), objectArrayService)
	})
	t.Run("filter type=api", func(t *testing.T) {
		ctx := newMockContext(t)
		var serviceType = "string-api"
		ctx.subjectManager.EXPECT().FindServices(gomock.Any(), "subject", &serviceType).Return(document.Service, nil)

		response, err := ctx.client.FindServices(nil, FindServicesRequestObject{
			Id: "subject",
			Params: FindServicesParams{
				Type: &serviceType,
			},
		})

		require.NoError(t, err)
		require.IsType(t, FindServices200JSONResponse{}, response)
		require.Len(t, response.(FindServices200JSONResponse), 4)
	})
	t.Run("filter endpointType=string", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().FindServices(gomock.Any(), "subject", nil).Return(document.Service, nil)
		var endpointType FindServicesParamsEndpointType = "string"

		response, err := ctx.client.FindServices(nil, FindServicesRequestObject{
			Id: "subject",
			Params: FindServicesParams{
				EndpointType: &endpointType,
			},
		})

		require.NoError(t, err)
		require.IsType(t, FindServices200JSONResponse{}, response)
		require.Len(t, response.(FindServices200JSONResponse), 1)
		assert.Equal(t, stringService, response.(FindServices200JSONResponse)[0])
	})
	t.Run("filter endpointType=object", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().FindServices(gomock.Any(), "subject", nil).Return(document.Service, nil)
		var endpointType FindServicesParamsEndpointType = "object"

		response, err := ctx.client.FindServices(nil, FindServicesRequestObject{
			Id: "subject",
			Params: FindServicesParams{
				EndpointType: &endpointType,
			},
		})

		require.NoError(t, err)
		require.IsType(t, FindServices200JSONResponse{}, response)
		require.Len(t, response.(FindServices200JSONResponse), 1)
		assert.Equal(t, objectService, response.(FindServices200JSONResponse)[0])
	})
	t.Run("filter endpointType=array", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().FindServices(gomock.Any(), "subject", nil).Return(document.Service, nil)
		var endpointType FindServicesParamsEndpointType = "array"

		response, err := ctx.client.FindServices(nil, FindServicesRequestObject{
			Id: "subject",
			Params: FindServicesParams{
				EndpointType: &endpointType,
			},
		})

		require.NoError(t, err)
		require.IsType(t, FindServices200JSONResponse{}, response)
		require.Len(t, response.(FindServices200JSONResponse), 2)
		assert.Contains(t, response.(FindServices200JSONResponse), stringArrayService)
		assert.Contains(t, response.(FindServices200JSONResponse), objectArrayService)
	})
	t.Run("error", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().FindServices(gomock.Any(), "subject", nil).Return(nil, assert.AnError)

		response, err := ctx.client.FindServices(nil, FindServicesRequestObject{
			Id: "subject",
		})

		assert.ErrorIs(t, err, assert.AnError)
		assert.Nil(t, response)
	})
}

func TestWrapper_AddVerificationMethod(t *testing.T) {
	vm := did.VerificationMethod{ID: did.MustParseDIDURL("did:example:1#key-1")}
	t.Run("ok - defaults", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().AddVerificationMethod(gomock.Any(), "subject", orm.AssertionKeyUsage()).Return([]did.VerificationMethod{vm}, nil)

		response, err := ctx.client.AddVerificationMethod(nil, AddVerificationMethodRequestObject{
			Id: "subject",
		})

		require.NoError(t, err)
		require.Len(t, response.(AddVerificationMethod200JSONResponse), 1)
	})
	t.Run("with encryption key", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.subjectManager.EXPECT().AddVerificationMethod(gomock.Any(), "subject", orm.AssertionKeyUsage()^orm.EncryptionKeyUsage()).Return([]did.VerificationMethod{vm}, nil)

		_, err := ctx.client.AddVerificationMethod(nil, AddVerificationMethodRequestObject{
			Id: "subject",
			Body: &KeyCreationOptions{
				AssertionKey:  true,
				EncryptionKey: true,
			},
		})

		require.NoError(t, err)
	})
	t.Run("error on no keys", func(t *testing.T) {
		ctx := newMockContext(t)

		_, err := ctx.client.AddVerificationMethod(nil, AddVerificationMethodRequestObject{
			Id: "subject",
			Body: &KeyCreationOptions{
				AssertionKey:  false,
				EncryptionKey: false,
			},
		})

		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(core.HTTPStatusCodeError).StatusCode())
	})
}

type mockContext struct {
	ctrl           *gomock.Controller
	vdr            *vdr.MockVDR
	subjectManager *didsubject.MockSubjectManager
	didResolver    *resolver.MockDIDResolver
	documentOwner  *didsubject.MockDocumentOwner
	client         *Wrapper
	requestCtx     context.Context
}

func newMockContext(t *testing.T) mockContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	didResolver := resolver.NewMockDIDResolver(ctrl)
	vdr := vdr.NewMockVDR(ctrl)
	subjectManager := didsubject.NewMockSubjectManager(ctrl)
	documentOwner := didsubject.NewMockDocumentOwner(ctrl)
	vdr.EXPECT().Resolver().Return(didResolver).AnyTimes()
	vdr.EXPECT().DocumentOwner().Return(documentOwner).AnyTimes()
	client := &Wrapper{VDR: vdr, SubjectManager: subjectManager}
	requestCtx := audit.TestContext()

	return mockContext{
		ctrl:           ctrl,
		vdr:            vdr,
		subjectManager: subjectManager,
		didResolver:    didResolver,
		documentOwner:  documentOwner,
		client:         client,
		requestCtx:     requestCtx,
	}
}
