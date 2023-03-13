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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/nuts-foundation/nuts-node/audit"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testDIDA = vdr.TestDIDA
var testDIDB = vdr.TestDIDB

func TestDidman_Name(t *testing.T) {
	instance := NewDidmanInstance(nil, nil, nil, nil, nil).(core.Named)

	assert.Equal(t, ModuleName, instance.Name())
}

func TestNewDidmanInstance(t *testing.T) {
	ctx := newMockContext(t)
	instance := NewDidmanInstance(ctx.docResolver, ctx.store, ctx.vdr, ctx.vcr, nil).(*didman)

	assert.NotNil(t, instance)
	assert.Equal(t, ctx.docResolver, instance.docResolver)
	assert.Equal(t, ctx.store, instance.store)
	assert.Equal(t, ctx.vdr, instance.vdr)
}

func TestDidman_AddEndpoint(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/v1")
	meta := &types.DocumentMetadata{Hash: hash.EmptyHash()}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		doc := &did.Document{}
		var newDoc did.Document
		ctx.docResolver.EXPECT().Resolve(testDIDA, nil).Return(doc, meta, nil)
		ctx.vdr.EXPECT().Update(ctx.audit, testDIDA, gomock.Any()).DoAndReturn(
			func(_ interface{}, _ interface{}, doc did.Document) error {
				newDoc = doc
				return nil
			})

		ep, err := ctx.instance.AddEndpoint(ctx.audit, testDIDA, "type", *u)

		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(ep.ID.String(), vdr.TestDIDA.String()))
		assert.Equal(t, "type", ep.Type)
		assert.Equal(t, u.String(), ep.ServiceEndpoint.(string))

		assert.Len(t, newDoc.Service, 1)
		assert.Equal(t, "type", newDoc.Service[0].Type)
		assert.Equal(t, u.String(), newDoc.Service[0].ServiceEndpoint)
		assert.Contains(t, newDoc.Service[0].ID.String(), vdr.TestDIDA.String())
	})

	t.Run("error - update failed", func(t *testing.T) {
		ctx := newMockContext(t)
		doc := &did.Document{}
		returnError := errors.New("b00m!")
		ctx.docResolver.EXPECT().Resolve(testDIDA, nil).Return(doc, meta, nil)
		ctx.vdr.EXPECT().Update(ctx.audit, testDIDA, gomock.Any()).Return(returnError)

		_, err := ctx.instance.AddEndpoint(ctx.audit, testDIDA, "type", *u)

		assert.Equal(t, returnError, err)
	})

	t.Run("error - duplicate service", func(t *testing.T) {
		ctx := newMockContext(t)
		doc := &did.Document{}
		ctx.docResolver.EXPECT().Resolve(testDIDA, nil).Return(doc, meta, nil).Times(2)
		ctx.vdr.EXPECT().Update(ctx.audit, testDIDA, gomock.Any()).DoAndReturn(
			func(_ context.Context, _ interface{}, doc did.Document) error {
				return vdr.ManagedDocumentValidator(didservice.NewServiceResolver(ctx.docResolver)).Validate(doc)
			}) //.Times(2)

		_, _ = ctx.instance.AddEndpoint(ctx.audit, testDIDA, "type", *u)
		_, err := ctx.instance.AddEndpoint(ctx.audit, testDIDA, "type", *u)

		assert.ErrorIs(t, err, types.ErrDuplicateService)
	})

	t.Run("error - DID not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(testDIDA, nil).Return(nil, nil, types.ErrNotFound)

		_, err := ctx.instance.AddEndpoint(ctx.audit, testDIDA, "type", *u)

		assert.Equal(t, types.ErrNotFound, err)
	})
}

func TestDidman_AddCompoundService(t *testing.T) {
	meta := &types.DocumentMetadata{Hash: hash.EmptyHash()}

	helloServiceQuery := didservice.MakeServiceReference(testDIDA, "hello")
	worldServiceQuery := didservice.MakeServiceReference(testDIDB, "world")
	universeServiceQuery := didservice.MakeServiceReference(testDIDB, "universe")
	universeNestedServiceQuery := didservice.MakeServiceReference(testDIDB, "universe-ref")
	references := make(map[string]ssi.URI, 0)
	references["hello"] = helloServiceQuery
	references["world"] = worldServiceQuery
	references["universe"] = universeServiceQuery

	expectedRefs := map[string]interface{}{}
	for k, v := range references {
		expectedRefs[k] = v.String()
	}

	serviceID := ssi.MustParseURI(fmt.Sprintf("%s#1", vdr.TestDIDA.String()))
	docA := did.Document{
		Context: []ssi.URI{did.DIDContextV1URI()},
		ID:      testDIDA,
		Service: []did.Service{{
			ID:              serviceID,
			Type:            "hello",
			ServiceEndpoint: "http://hello",
		}},
	}
	docB := did.Document{
		Context: []ssi.URI{did.DIDContextV1URI()},
		ID:      testDIDB,
		Service: []did.Service{
			{
				Type:            "world",
				ServiceEndpoint: "http://world",
			},
			{
				Type:            "universe",
				ServiceEndpoint: "http://universe",
			},
			{
				Type:            "universe-ref",
				ServiceEndpoint: vdr.TestDIDB.String() + "/serviceEndpoint?type=universe",
			},
			{
				Type:            "cyclic-ref",
				ServiceEndpoint: vdr.TestDIDB.String() + "/serviceEndpoint?type=cyclic-ref",
			},
		},
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		var newDoc did.Document
		ctx.docResolver.EXPECT().Resolve(testDIDA, nil).MinTimes(1).Return(&docA, meta, nil)
		// DID B should be resolved once, since they're cached
		ctx.docResolver.EXPECT().Resolve(testDIDB, nil).Return(&docB, meta, nil)
		ctx.vdr.EXPECT().Update(ctx.audit, testDIDA, gomock.Any()).DoAndReturn(
			func(_ context.Context, _ interface{}, doc did.Document) error {
				newDoc = doc
				return vdr.ManagedDocumentValidator(didservice.NewServiceResolver(ctx.docResolver)).Validate(newDoc)
			})

		_, err := ctx.instance.AddCompoundService(ctx.audit, testDIDA, "helloworld", references)

		require.NoError(t, err)
		assert.Len(t, newDoc.Service, 2)
		assert.Equal(t, "helloworld", newDoc.Service[1].Type)
		assert.Equal(t, expectedRefs, newDoc.Service[1].ServiceEndpoint)
	})
	t.Run("ok - nested reference", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(testDIDB, nil).MinTimes(1).Return(&docB, meta, nil)
		ctx.vdr.EXPECT().Update(ctx.audit, testDIDB, gomock.Any())

		_, err := ctx.instance.AddCompoundService(ctx.audit, testDIDB, "helloworld", map[string]ssi.URI{"foobar": universeNestedServiceQuery})

		assert.NoError(t, err)
	})
	t.Run("ok - endpoint is an absolute URL", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(testDIDA, nil).MinTimes(1).Return(&docA, meta, nil)
		ctx.vdr.EXPECT().Update(ctx.audit, testDIDA, gomock.Any())

		s := ssi.MustParseURI("http://nuts.nl")
		_, err := ctx.instance.AddCompoundService(ctx.audit, testDIDA, "hellonuts", map[string]ssi.URI{"foobar": s})

		assert.NoError(t, err)
	})
}

func TestDidman_DeleteService(t *testing.T) {
	didDocStr := `{"service":[{"id":"did:nuts:123#1", "serviceEndpoint": "https://api.example.com"}]}`
	doc := func() *did.Document {
		didDoc := &did.Document{}
		json.Unmarshal([]byte(didDocStr), didDoc)
		return didDoc
	}
	id, _ := did.ParseDID("did:nuts:123")
	uri := ssi.MustParseURI("did:nuts:123#1")
	meta := &types.DocumentMetadata{Hash: hash.EmptyHash()}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		var newDoc did.Document
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(doc(), meta, nil)
		ctx.store.EXPECT().Iterate(gomock.Any()).Return(nil)
		ctx.vdr.EXPECT().Update(ctx.audit, *id, gomock.Any()).DoAndReturn(
			func(_ context.Context, _ interface{}, doc interface{}) error {
				newDoc = doc.(did.Document)
				return nil
			})

		err := ctx.instance.DeleteService(ctx.audit, uri)

		require.NoError(t, err)
		assert.Len(t, newDoc.Service, 0)
	})

	t.Run("error - service not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(doc(), meta, nil)
		ctx.store.EXPECT().Iterate(gomock.Any()).Return(nil)
		nonExistingID := uri
		nonExistingID.Fragment = "non-existent"

		err := ctx.instance.DeleteService(ctx.audit, nonExistingID)

		assert.Equal(t, types.ErrServiceNotFound, err)
	})

	t.Run("error - in use", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(doc(), meta, nil)
		ctx.store.EXPECT().Iterate(gomock.Any()).Return(ErrServiceInUse)

		err := ctx.instance.DeleteService(ctx.audit, uri)

		assert.Equal(t, ErrServiceInUse, err)
	})

	t.Run("error - update failed", func(t *testing.T) {
		ctx := newMockContext(t)
		returnError := errors.New("b00m!")
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(doc(), meta, nil)
		ctx.store.EXPECT().Iterate(gomock.Any()).Return(nil)
		ctx.vdr.EXPECT().Update(ctx.audit, *id, gomock.Any()).Return(returnError)

		err := ctx.instance.DeleteService(ctx.audit, uri)

		assert.Equal(t, returnError, err)
	})

	t.Run("error - DID not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(nil, nil, types.ErrNotFound)

		err := ctx.instance.DeleteService(ctx.audit, uri)

		assert.Equal(t, types.ErrNotFound, err)
	})
}

func TestDidman_UpdateContactInformation(t *testing.T) {
	didDoc := didservice.CreateDocument()
	id, _ := did.ParseDID("did:nuts:123")
	didDoc.ID = *id
	meta := &types.DocumentMetadata{Hash: hash.EmptyHash()}
	expected := ContactInformation{
		Email:   "email",
		Name:    "name",
		Phone:   "phone",
		Website: "website",
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(&didDoc, meta, nil)

		var actualDocument did.Document
		ctx.vdr.EXPECT().Update(ctx.audit, *id, gomock.Any()).
			DoAndReturn(func(_ context.Context, _ did.DID, doc did.Document) error {
				actualDocument = doc
				// trigger validation to check if the added contact information isn't wrong
				return vdr.ManagedDocumentValidator(nil).Validate(doc)
			})
		actual, err := ctx.instance.UpdateContactInformation(ctx.audit, *id, expected)
		require.NoError(t, err)
		assert.Equal(t, expected, *actual)
		services := filterServices(&actualDocument, ContactInformationServiceType)
		assert.Len(t, services, 1)
		actualInfo := ContactInformation{}
		services[0].UnmarshalServiceEndpoint(&actualInfo)
		assert.NotEmpty(t, services[0].ID)
		assert.Equal(t, "node-contact-info", services[0].Type)
		assert.Equal(t, expected, actualInfo)
	})
	t.Run("replaces existing, mixed with other services", func(t *testing.T) {
		ctx := newMockContext(t)
		didDoc := &did.Document{}
		didDoc.Service = append(didDoc.Service, did.Service{
			Type: "node-contact-info",
			ServiceEndpoint: ContactInformation{
				Email:   "before",
				Name:    "before",
				Phone:   "before",
				Website: "before",
			},
		}, did.Service{
			Type:            "other-type",
			ServiceEndpoint: "foobar",
		})
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, meta, nil)
		var actualDocument did.Document
		ctx.vdr.EXPECT().Update(ctx.audit, *id, gomock.Any()).
			Do(func(_ context.Context, _ did.DID, doc did.Document) {
				actualDocument = doc
			})
		actual, err := ctx.instance.UpdateContactInformation(ctx.audit, *id, expected)
		require.NoError(t, err)
		assert.Equal(t, expected, *actual)
		services := filterServices(&actualDocument, ContactInformationServiceType)
		assert.Len(t, services, 1)
		actualInfo := ContactInformation{}
		services[0].UnmarshalServiceEndpoint(&actualInfo)
		assert.NotEmpty(t, services[0].ID)
		assert.Equal(t, "node-contact-info", services[0].Type)
		assert.Equal(t, expected, actualInfo)
	})
}

func TestDidman_GetContactInformation(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	meta := &types.DocumentMetadata{Hash: hash.EmptyHash()}
	expected := ContactInformation{
		Email:   "email",
		Name:    "name",
		Phone:   "phone",
		Website: "website",
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		didDoc := &did.Document{Service: []did.Service{{
			Type:            "node-contact-info",
			ServiceEndpoint: expected,
		}}}
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, meta, nil)
		actual, err := ctx.instance.GetContactInformation(*id)
		assert.NoError(t, err)
		assert.Equal(t, expected, *actual)
	})
	t.Run("no contact info", func(t *testing.T) {
		ctx := newMockContext(t)
		didDoc := &did.Document{}
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, meta, nil)
		actual, err := ctx.instance.GetContactInformation(*id)
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
	t.Run("error - can't resolve DID", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(nil, nil, errors.New("failed"))
		actual, err := ctx.instance.GetContactInformation(*id)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
	t.Run("error - invalid contact info", func(t *testing.T) {
		ctx := newMockContext(t)
		didDoc := &did.Document{Service: []did.Service{{
			Type:            "node-contact-info",
			ServiceEndpoint: "hello, world!",
		}}}
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, meta, nil)
		actual, err := ctx.instance.GetContactInformation(*id)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
	t.Run("error - multiple contact info services", func(t *testing.T) {
		ctx := newMockContext(t)
		svc := did.Service{
			Type:            "node-contact-info",
			ServiceEndpoint: expected,
		}
		didDoc := &did.Document{Service: []did.Service{svc, svc}}
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, meta, nil)
		actual, err := ctx.instance.GetContactInformation(*id)
		assert.EqualError(t, err, "multiple contact information services found")
		assert.Nil(t, actual)
	})
}

func TestDidman_DeleteEndpointsByType(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	serviceID := *id
	serviceID.Fragment = "abc"
	endpointType := "eOverdracht"
	endpoints := []did.Service{{
		ID:              serviceID.URI(),
		Type:            endpointType,
		ServiceEndpoint: map[string]interface{}{"foo": "http://example.org"},
	}}

	meta := &types.DocumentMetadata{Hash: hash.EmptyHash()}
	didDoc := &did.Document{ID: *id, Service: endpoints}

	t.Run("ok - it deletes the service", func(t *testing.T) {
		// local copy to prevent actually deleting the service from the test document
		didDoc := &did.Document{ID: *id, Service: endpoints}
		ctx := newMockContext(t)
		ctx.vdr.EXPECT().Update(ctx.audit, *id, gomock.Any()).DoAndReturn(
			func(_ context.Context, _ interface{}, doc did.Document) error {
				assert.Len(t, doc.Service, 0)
				return nil
			})
		// not in use by any other document
		ctx.store.EXPECT().Iterate(gomock.Any()).Return(nil)
		ctx.docResolver.EXPECT().Resolve(*id, gomock.Any()).Return(didDoc, meta, nil).Times(2)
		err := ctx.instance.DeleteEndpointsByType(ctx.audit, *id, endpointType)
		assert.NoError(t, err)
	})

	t.Run("ok - it keeps other services", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vdr.EXPECT().Update(ctx.audit, *id, gomock.Any()).DoAndReturn(
			func(_ context.Context, _ interface{}, doc did.Document) error {
				assert.Len(t, doc.Service, 1)
				return nil
			})
		otherServiceID := ssi.MustParseURI("did:nuts:123#def")
		otherService := did.Service{
			ID:   otherServiceID,
			Type: "other",
		}
		didDocWithOtherService := &did.Document{ID: *id, Service: append(endpoints, otherService)}
		// not in use by any other document
		ctx.store.EXPECT().Iterate(gomock.Any()).Return(nil)
		ctx.docResolver.EXPECT().Resolve(*id, gomock.Any()).Return(didDocWithOtherService, meta, nil).Times(2)
		err := ctx.instance.DeleteEndpointsByType(ctx.audit, *id, endpointType)
		assert.NoError(t, err)
	})

	t.Run("error - unknown service type", func(t *testing.T) {
		ctx := newMockContext(t)
		// not in use by any other document
		ctx.docResolver.EXPECT().Resolve(*id, gomock.Any()).Return(didDoc, meta, nil)
		err := ctx.instance.DeleteEndpointsByType(ctx.audit, *id, "unknown type")
		assert.ErrorIs(t, err, types.ErrServiceNotFound)
	})

	t.Run("error - DID document", func(t *testing.T) {
		ctx := newMockContext(t)
		// not in use by any other document
		ctx.docResolver.EXPECT().Resolve(*id, gomock.Any()).Return(nil, nil, types.ErrNotFound)
		err := ctx.instance.DeleteEndpointsByType(ctx.audit, *id, endpointType)
		assert.ErrorIs(t, err, types.ErrNotFound)
	})

	t.Run("error - in use by other services", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.store.EXPECT().Iterate(gomock.Any()).Return(ErrServiceInUse)
		ctx.docResolver.EXPECT().Resolve(*id, gomock.Any()).Return(didDoc, meta, nil).Times(2)
		err := ctx.instance.DeleteEndpointsByType(ctx.audit, *id, endpointType)
		assert.ErrorIs(t, err, ErrServiceInUse)
	})
}

func TestDidman_GetCompoundServices(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	expected := []did.Service{{
		Type:            "eOverdracht",
		ServiceEndpoint: map[string]interface{}{"foo": "http://example.org"},
	}}
	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		didDoc := &did.Document{Service: expected}
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServices(*id)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("ok - it ignores contact info", func(t *testing.T) {
		ctx := newMockContext(t)
		didDoc := &did.Document{Service: append(expected, did.Service{Type: ContactInformationServiceType, ServiceEndpoint: map[string]interface{}{}})}
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServices(*id)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("ok - it ignores endpoint services", func(t *testing.T) {
		ctx := newMockContext(t)
		didDoc := &did.Document{Service: append(expected, did.Service{Type: "normal-service", ServiceEndpoint: "http://api.example.com/fhir"})}
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServices(*id)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("error - unknown DID", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(nil, nil, types.ErrNotFound)
		actual, err := ctx.instance.GetCompoundServices(*id)
		assert.EqualError(t, err, "unable to find the DID document")
		assert.Nil(t, actual)
	})
}

func TestDidman_GetCompoundServiceEndpoint(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	expectedRef := id.String() + "/serviceEndpoint?type=url"
	expectedURL := "http://example.org"
	didDoc := &did.Document{Service: []did.Service{
		{
			Type: "csType",
			ServiceEndpoint: map[string]interface{}{
				"eType": expectedRef,
			},
		},
		{
			Type: "csTypeNoRefs",
			ServiceEndpoint: map[string]interface{}{
				"eType": expectedURL,
			},
		},
		{
			Type:            "csRefType",
			ServiceEndpoint: id.String() + "/serviceEndpoint?type=csType",
		},
		{
			Type:            "url",
			ServiceEndpoint: expectedURL,
		},
		{
			Type: "csInvalidType",
			ServiceEndpoint: map[string]interface{}{
				"non-url": true,
			},
		},
	}, ID: *id}
	t.Run("ok - resolve references", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csType", "eType", true)
		assert.NoError(t, err)
		assert.Equal(t, expectedURL, actual)
	})
	t.Run("ok - no references", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csTypeNoRefs", "eType", true)
		assert.NoError(t, err)
		assert.Equal(t, expectedURL, actual)
	})
	t.Run("ok - resolve references - top level is compound service", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csType", "eType", false)
		assert.NoError(t, err)
		assert.Equal(t, expectedRef, actual)
	})
	t.Run("ok - resolve references - top level is reference", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csRefType", "eType", false)
		assert.NoError(t, err)
		assert.Equal(t, expectedRef, actual)
	})
	t.Run("error - unknown DID", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(nil, nil, types.ErrNotFound)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csType", "eType", false)
		assert.ErrorIs(t, err, types.ErrNotFound)
		assert.Empty(t, actual)
	})
	t.Run("error - unknown compound service", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "non-existent", "eType", false)
		assert.Contains(t, err.Error(), types.ErrServiceNotFound.Error())
		assert.Empty(t, actual)
	})
	t.Run("error - unknown endpoint", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csType", "non-existent", false)
		assert.ErrorIs(t, err, types.ErrServiceNotFound)
		assert.Empty(t, actual)
	})
	t.Run("error - endpoint is not an URL", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csInvalidType", "non-url", false)
		assert.ErrorIs(t, err, ErrReferencedServiceNotAnEndpoint{})
		assert.Empty(t, actual)
	})
	t.Run("ok - resolve endpoint (nuts-registry-admin-demo structure)", func(t *testing.T) {
		expectedURL := "http://localhost:1304/web/external/transfer/notify"
		careProvider := `{"@context":"https://www.w3.org/ns/did/v1","id":"did:nuts:8XB5WdtaxK7NZQs3onvGsRVkUSQtjWwcgRTCLtgxDAYT","service":[{"id":"did:nuts:8XB5WdtaxK7NZQs3onvGsRVkUSQtjWwcgRTCLtgxDAYT#7P8jAUReCUuAJSFoYNo75BAkdRiwFeudHaCLfyqyVkVo","serviceEndpoint":"did:nuts:5bSHwHtpSZfSCdCqaHvzDceEkjgNuKvTWVvQPB5DdeD9/serviceEndpoint?type=eOverdracht-receiver","type":"eOverdracht-receiver"}]}`
		saasProvider := `{"@context":"https://www.w3.org/ns/did/v1","id":"did:nuts:5bSHwHtpSZfSCdCqaHvzDceEkjgNuKvTWVvQPB5DdeD9","service":[{"id":"did:nuts:5bSHwHtpSZfSCdCqaHvzDceEkjgNuKvTWVvQPB5DdeD9#BDtdeE3RGY1FoqW6zvAcMZTmGyQi1kr6GANfeEXbPufc","serviceEndpoint":"http://localhost:8080/fhir","type":"eoverdracht-fhir"},{"id":"did:nuts:5bSHwHtpSZfSCdCqaHvzDceEkjgNuKvTWVvQPB5DdeD9#DX7ZbdjbqVXYEfC83WKqisyrqrQ6sRcgrXXU63jNaHqp","serviceEndpoint":"http://localhost:1304/web/external/transfer/notify","type":"eoverdracht-notification-receiver"},{"id":"did:nuts:5bSHwHtpSZfSCdCqaHvzDceEkjgNuKvTWVvQPB5DdeD9#22LyurnBCyAJCtyzQkEq1MXqEfdP1ZNpWr1sy5REDJ34","serviceEndpoint":"http://localhost:1323/n2n/auth/v1/accesstoken","type":"oauth-request-accesstoken"},{"id":"did:nuts:5bSHwHtpSZfSCdCqaHvzDceEkjgNuKvTWVvQPB5DdeD9#6UYBLQVCZ4WWRRg2yuqqE4k727Vf5gvMEiPYMxAD5o1Y","serviceEndpoint":{"notification":"did:nuts:5bSHwHtpSZfSCdCqaHvzDceEkjgNuKvTWVvQPB5DdeD9/serviceEndpoint?type=eoverdracht-notification-receiver","oauth":"did:nuts:5bSHwHtpSZfSCdCqaHvzDceEkjgNuKvTWVvQPB5DdeD9/serviceEndpoint?type=oauth-request-accesstoken"},"type":"eOverdracht-receiver"},{"id":"did:nuts:5bSHwHtpSZfSCdCqaHvzDceEkjgNuKvTWVvQPB5DdeD9#4ECP4tF6PTvk1nH9bcA7oA9yrsTA93iDADUqLn6vK7uF","serviceEndpoint":{"fhir":"did:nuts:5bSHwHtpSZfSCdCqaHvzDceEkjgNuKvTWVvQPB5DdeD9/serviceEndpoint?type=eoverdracht-fhir"},"type":"eOverdracht-sender"}]}`

		careProviderDocument := &did.Document{}
		err := careProviderDocument.UnmarshalJSON([]byte(careProvider))
		require.NoError(t, err)

		saasProviderDocument := &did.Document{}
		err = saasProviderDocument.UnmarshalJSON([]byte(saasProvider))
		require.NoError(t, err)

		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(careProviderDocument.ID, nil).Return(careProviderDocument, nil, nil)
		ctx.docResolver.EXPECT().Resolve(saasProviderDocument.ID, nil).Return(saasProviderDocument, nil, nil)

		actualURL, err := ctx.instance.GetCompoundServiceEndpoint(careProviderDocument.ID, "eOverdracht-receiver", "notification", true)
		assert.NoError(t, err)
		assert.Equal(t, expectedURL, actualURL)
	})
}

func TestDidman_SearchOrganizations(t *testing.T) {
	docWithService := did.Document{
		ID: testDIDB,
		Service: []did.Service{{
			Type:            "eOverdracht",
			ServiceEndpoint: map[string]interface{}{"foo": "http://example.org"},
		}},
	}
	docWithoutService := did.Document{
		ID: testDIDB,
	}
	reqCtx := context.Background()
	searchTerms := []vcr.SearchTerm{
		{IRIPath: jsonld.OrganizationNamePath, Value: "query", Type: vcr.Prefix},
		{IRIPath: jsonld.OrganizationCityPath, Type: vcr.NotNil},
	}
	testCredential := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestOrganizationCredential), &testCredential)

	t.Run("ok - no results", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{}, nil)

		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", nil)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Empty(t, actual)
	})
	t.Run("ok - no DID service type", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)
		ctx.docResolver.EXPECT().Resolve(testDIDB, nil).Return(&docWithoutService, nil, nil)

		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", nil)

		assert.NoError(t, err)
		assert.Len(t, actual, 1)
	})
	t.Run("ok - with DID service type (matches)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)
		ctx.docResolver.EXPECT().Resolve(testDIDB, nil).Return(&docWithService, nil, nil)

		serviceType := "eOverdracht"
		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", &serviceType)

		assert.NoError(t, err)
		assert.Len(t, actual, 1)
	})
	t.Run("ok - with DID service type (no match)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)
		ctx.docResolver.EXPECT().Resolve(testDIDB, nil).Return(&docWithoutService, nil, nil)

		serviceType := "eOverdracht"
		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", &serviceType)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Empty(t, actual)
	})
	t.Run("ok - DID document not found (logs, omits result)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)
		ctx.docResolver.EXPECT().Resolve(testDIDB, nil).Return(nil, nil, types.ErrNotFound)

		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", nil)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Empty(t, actual)
	})
	t.Run("ok - DID document deactivated (logs, omits result)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)
		ctx.docResolver.EXPECT().Resolve(testDIDB, nil).Return(nil, nil, types.ErrDeactivated)

		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", nil)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Empty(t, actual)
	})
	t.Run("error - other error while resolving DID document", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)
		ctx.docResolver.EXPECT().Resolve(testDIDB, nil).Return(nil, nil, io.EOF)

		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", nil)

		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestKeyedMutex_Lock(t *testing.T) {
	t.Run("it locks for a certain key", func(t *testing.T) {
		km := keyedMutex{}
		unlockKeyFn := km.Lock("key")
		val, ok := km.mutexes.Load("key")
		assert.True(t, ok)
		m := val.(*sync.Mutex)

		assert.False(t, m.TryLock())
		unlockKeyFn()
		assert.True(t, m.TryLock())
	})
}

func TestGenerateIDForService(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/v1")
	expectedID := ssi.MustParseURI(fmt.Sprintf("%s#D4eNCVjdtGaeHYMdjsdYHpTQmiwXtQKJmE9QSwwsKKzy", vdr.TestDIDA.String()))

	id := generateIDForService(testDIDA, did.Service{
		Type:            "type",
		ServiceEndpoint: u.String(),
	})
	assert.Equal(t, expectedID, id)
}

func TestReferencesService(t *testing.T) {
	t.Run("false", func(t *testing.T) {
		didDocStr := `{"service":[{"id":"did:nuts:1234#1", "serviceEndpoint": {"ref":"did:nuts:123#2"}}]}`
		didDoc := did.Document{}
		json.Unmarshal([]byte(didDocStr), &didDoc)
		uri := ssi.MustParseURI("did:nuts:123#1")

		assert.False(t, referencesService(didDoc, uri))
	})

	t.Run("true", func(t *testing.T) {
		didDocStr := `{"service":[{"id":"did:nuts:1234#1", "serviceEndpoint": {"ref":"did:nuts:123#1"}}]}`
		didDoc := did.Document{}
		json.Unmarshal([]byte(didDocStr), &didDoc)
		uri := ssi.MustParseURI("did:nuts:123#1")

		assert.True(t, referencesService(didDoc, uri))
	})
}

type mockContext struct {
	ctrl        *gomock.Controller
	docResolver *types.MockDocResolver
	store       *didstore.MockStore
	vdr         *types.MockVDR
	vcr         *vcr.MockFinder
	instance    Didman
	audit       context.Context
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	docResolver := types.NewMockDocResolver(ctrl)
	store := didstore.NewMockStore(ctrl)
	mockVDR := types.NewMockVDR(ctrl)
	mockVCR := vcr.NewMockFinder(ctrl)
	instance := NewDidmanInstance(docResolver, store, mockVDR, mockVCR, jsonld.NewTestJSONLDManager(t))

	return mockContext{
		ctrl:        ctrl,
		docResolver: docResolver,
		store:       store,
		vdr:         mockVDR,
		vcr:         mockVCR,
		instance:    instance,
		audit:       audit.TestContext(),
	}
}
