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
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"io"
	"net/url"
	"strings"
	"sync"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var testDIDA = vdr.TestDIDA
var testDIDB = vdr.TestDIDB

func TestDidman_Name(t *testing.T) {
	instance := NewDidmanInstance(nil, nil, nil).(core.Named)

	assert.Equal(t, ModuleName, instance.Name())
}

func TestNewDidmanInstance(t *testing.T) {
	ctx := newMockContext(t)
	instance := NewDidmanInstance(ctx.vdr, ctx.vcr, nil).(*didman)

	assert.NotNil(t, instance)
	assert.Equal(t, ctx.vcr, instance.vcr)
	assert.Equal(t, ctx.vdr, instance.vdr)
}

func TestDidman_AddEndpoint(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/v1")
	meta := &resolver.DocumentMetadata{Hash: hash.EmptyHash()}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		doc := &did.Document{}
		var newDoc did.Document
		ctx.didResolver.EXPECT().Resolve(testDIDA, nil).Return(doc, meta, nil)
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
		ctx.didResolver.EXPECT().Resolve(testDIDA, nil).Return(doc, meta, nil)
		ctx.vdr.EXPECT().Update(ctx.audit, testDIDA, gomock.Any()).Return(returnError)

		_, err := ctx.instance.AddEndpoint(ctx.audit, testDIDA, "type", *u)

		assert.Equal(t, returnError, err)
	})

	t.Run("error - duplicate service", func(t *testing.T) {
		ctx := newMockContext(t)
		doc := &did.Document{}
		ctx.didResolver.EXPECT().Resolve(testDIDA, nil).Return(doc, meta, nil).Times(2)
		ctx.vdr.EXPECT().Update(ctx.audit, testDIDA, gomock.Any()).DoAndReturn(
			func(_ context.Context, _ interface{}, doc did.Document) error {
				return didnuts.ManagedDocumentValidator(nil).Validate(doc)
			}) //.Times(2)

		_, _ = ctx.instance.AddEndpoint(ctx.audit, testDIDA, "type", *u)
		_, err := ctx.instance.AddEndpoint(ctx.audit, testDIDA, "type", *u)

		assert.ErrorIs(t, err, resolver.ErrDuplicateService)
	})

	t.Run("error - DID not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(testDIDA, nil).Return(nil, nil, resolver.ErrNotFound)

		_, err := ctx.instance.AddEndpoint(ctx.audit, testDIDA, "type", *u)

		assert.Equal(t, resolver.ErrNotFound, err)
	})
}

func TestDidman_UpdateEndpoint(t *testing.T) {
	endpoint, _ := url.Parse("https://api.example.com/v1")
	newEndpoint, _ := url.Parse("https://api.example.com/v2")
	meta := &resolver.DocumentMetadata{Hash: hash.EmptyHash()}
	const serviceType = "type"
	service := did.Service{
		Type:            serviceType,
		ServiceEndpoint: endpoint.String(),
	}
	document := &did.Document{
		Service: []did.Service{service},
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		var updatedDocument did.Document
		ctx.didResolver.EXPECT().Resolve(testDIDA, nil).Return(document, meta, nil)
		ctx.vdr.EXPECT().Update(ctx.audit, testDIDA, gomock.Any()).DoAndReturn(
			func(_ interface{}, _ interface{}, doc did.Document) error {
				updatedDocument = doc
				return nil
			})

		ep, err := ctx.instance.UpdateEndpoint(ctx.audit, testDIDA, serviceType, *newEndpoint)

		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(ep.ID.String(), vdr.TestDIDA.String()))
		assert.Equal(t, serviceType, ep.Type)
		assert.Equal(t, newEndpoint.String(), ep.ServiceEndpoint.(string))

		assert.Len(t, updatedDocument.Service, 1)
		assert.Equal(t, serviceType, updatedDocument.Service[0].Type)
		assert.Equal(t, newEndpoint.String(), updatedDocument.Service[0].ServiceEndpoint)
		assert.Contains(t, updatedDocument.Service[0].ID.String(), vdr.TestDIDA.String())
		assert.NotEqual(t, updatedDocument.Service[0].ID.String(), service.ID.String())
	})

	t.Run("error - update failed", func(t *testing.T) {
		ctx := newMockContext(t)
		returnError := errors.New("b00m!")
		ctx.didResolver.EXPECT().Resolve(testDIDA, nil).Return(document, meta, nil)
		ctx.vdr.EXPECT().Update(ctx.audit, testDIDA, gomock.Any()).Return(returnError)

		_, err := ctx.instance.UpdateEndpoint(ctx.audit, testDIDA, serviceType, *endpoint)

		assert.Equal(t, returnError, err)
	})

	t.Run("error - service not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(testDIDA, nil).Return(document, meta, nil)

		_, err := ctx.instance.UpdateEndpoint(ctx.audit, testDIDA, "some-other-type", *endpoint)

		assert.Equal(t, resolver.ErrServiceNotFound, err)
	})

	t.Run("error - DID not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(testDIDA, nil).Return(nil, nil, resolver.ErrNotFound)

		_, err := ctx.instance.AddEndpoint(ctx.audit, testDIDA, serviceType, *endpoint)

		assert.Equal(t, resolver.ErrNotFound, err)
	})
}

func TestDidman_AddCompoundService(t *testing.T) {
	meta := &resolver.DocumentMetadata{Hash: hash.EmptyHash()}

	helloServiceQuery := resolver.MakeServiceReference(testDIDA, "hello")
	worldServiceQuery := resolver.MakeServiceReference(testDIDB, "world")
	universeServiceQuery := resolver.MakeServiceReference(testDIDB, "universe")
	universeNestedServiceQuery := resolver.MakeServiceReference(testDIDB, "universe-ref")
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
		Context: []interface{}{did.DIDContextV1URI()},
		ID:      testDIDA,
		Service: []did.Service{{
			ID:              serviceID,
			Type:            "hello",
			ServiceEndpoint: "http://hello",
		}},
	}
	docB := did.Document{
		Context: []interface{}{did.DIDContextV1URI()},
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
		ctx.didResolver.EXPECT().Resolve(testDIDA, nil).MinTimes(1).Return(&docA, meta, nil)
		ctx.didResolver.EXPECT().Resolve(testDIDB, nil).MinTimes(1).Return(&docB, meta, nil)
		ctx.vdr.EXPECT().Update(ctx.audit, testDIDA, gomock.Any()).DoAndReturn(
			func(_ context.Context, _ interface{}, doc did.Document) error {
				newDoc = doc
				return didnuts.ManagedDocumentValidator(resolver.DIDServiceResolver{Resolver: ctx.didResolver}).Validate(newDoc)
			})

		_, err := ctx.instance.AddCompoundService(ctx.audit, testDIDA, "helloworld", references)

		require.NoError(t, err)
		assert.Len(t, newDoc.Service, 2)
		assert.Equal(t, "helloworld", newDoc.Service[1].Type)
		assert.Equal(t, expectedRefs, newDoc.Service[1].ServiceEndpoint)
	})
	t.Run("ok - nested reference", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(testDIDB, nil).MinTimes(1).Return(&docB, meta, nil)
		ctx.vdr.EXPECT().Update(ctx.audit, testDIDB, gomock.Any())

		_, err := ctx.instance.AddCompoundService(ctx.audit, testDIDB, "helloworld", map[string]ssi.URI{"foobar": universeNestedServiceQuery})

		assert.NoError(t, err)
	})
	t.Run("ok - endpoint is an absolute URL", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(testDIDA, nil).MinTimes(1).Return(&docA, meta, nil)
		ctx.vdr.EXPECT().Update(ctx.audit, testDIDA, gomock.Any())

		s := ssi.MustParseURI("http://nuts.nl")
		_, err := ctx.instance.AddCompoundService(ctx.audit, testDIDA, "hellonuts", map[string]ssi.URI{"foobar": s})

		assert.NoError(t, err)
	})
}

func TestDidman_UpdateCompoundService(t *testing.T) {
	meta := &resolver.DocumentMetadata{Hash: hash.EmptyHash()}

	helloServiceQuery := resolver.MakeServiceReference(testDIDA, "hello")
	worldServiceQuery := resolver.MakeServiceReference(testDIDB, "world")
	universeServiceQuery := resolver.MakeServiceReference(testDIDB, "universe")
	references := make(map[string]ssi.URI, 0)
	references["hello"] = helloServiceQuery
	references["world"] = worldServiceQuery
	references["universe"] = universeServiceQuery

	expectedRefs := map[string]interface{}{}
	for k, v := range references {
		expectedRefs[k] = v.String()
	}

	document := did.Document{
		Context: []interface{}{did.DIDContextV1URI()},
		ID:      testDIDA,
		Service: []did.Service{
			{
				ID:              ssi.MustParseURI(fmt.Sprintf("%s#1", vdr.TestDIDA.String())),
				Type:            "hello",
				ServiceEndpoint: "http://hello",
			},
			{
				ID:              ssi.MustParseURI(fmt.Sprintf("%s#2", vdr.TestDIDA.String())),
				Type:            "hellonuts",
				ServiceEndpoint: testDIDA.String() + "/serviceEndpoint?type=hello",
			},
		},
	}
	t.Run("ok", func(t *testing.T) {
		var updatedDocument did.Document
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(testDIDA, nil).MinTimes(1).Return(&document, meta, nil)
		ctx.vdr.EXPECT().Update(ctx.audit, testDIDA, gomock.Any()).DoAndReturn(
			func(_ interface{}, _ interface{}, doc did.Document) error {
				updatedDocument = doc
				return nil
			},
		)

		s := ssi.MustParseURI("http://nuts.nl")
		newService := map[string]ssi.URI{"foobar": s}
		_, err := ctx.instance.UpdateCompoundService(ctx.audit, testDIDA, "hellonuts", newService)

		require.NoError(t, err)
		assert.Equal(t, newService["foobar"].String(), updatedDocument.Service[1].ServiceEndpoint.(map[string]interface{})["foobar"])
	})
}

func TestDidman_DeleteService(t *testing.T) {
	didDocStr := `{"id":"did:nuts:123","service":[{"id":"did:nuts:123#1", "serviceEndpoint": "https://api.example.com", "type": "testType"}]}`
	doc := func(didDocString string) *did.Document {
		didDoc := &did.Document{}
		json.Unmarshal([]byte(didDocString), didDoc)
		return didDoc
	}
	id, _ := did.ParseDID("did:nuts:123")
	uri := ssi.MustParseURI("did:nuts:123#1")
	meta := &resolver.DocumentMetadata{Hash: hash.EmptyHash()}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		var newDoc did.Document
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(doc(didDocStr), meta, nil)
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
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(doc(didDocStr), meta, nil)
		nonExistingID := uri
		nonExistingID.Fragment = "non-existent"

		err := ctx.instance.DeleteService(ctx.audit, nonExistingID)

		assert.Equal(t, resolver.ErrServiceNotFound, err)
	})

	t.Run("error - in use", func(t *testing.T) {
		didDocStr := `{"id":"did:nuts:123",
			"service": [{"id":"did:nuts:123#1", "serviceEndpoint": "https://api.example.com", "type": "testType"}, 
						{"id":"did:nuts:123#2", "serviceEndpoint": "did:nuts:123/serviceEndpoint?type=testType", "type": "refType"}]}`
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(doc(didDocStr), meta, nil)

		err := ctx.instance.DeleteService(ctx.audit, uri)

		assert.Equal(t, ErrServiceInUse, err)
	})

	t.Run("error - update failed", func(t *testing.T) {
		ctx := newMockContext(t)
		returnError := errors.New("b00m!")
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(doc(didDocStr), meta, nil)
		ctx.vdr.EXPECT().Update(ctx.audit, *id, gomock.Any()).Return(returnError)

		err := ctx.instance.DeleteService(ctx.audit, uri)

		assert.Equal(t, returnError, err)
	})

	t.Run("error - DID not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(nil, nil, resolver.ErrNotFound)

		err := ctx.instance.DeleteService(ctx.audit, uri)

		assert.Equal(t, resolver.ErrNotFound, err)
	})
}

func TestDidman_UpdateContactInformation(t *testing.T) {
	didDoc := didnuts.CreateDocument()
	id, _ := did.ParseDID("did:nuts:123")
	didDoc.ID = *id
	meta := &resolver.DocumentMetadata{Hash: hash.EmptyHash()}
	expected := ContactInformation{
		Email:   "email",
		Name:    "name",
		Phone:   "phone",
		Website: "website",
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(&didDoc, meta, nil)

		var actualDocument did.Document
		ctx.vdr.EXPECT().Update(ctx.audit, *id, gomock.Any()).
			DoAndReturn(func(_ context.Context, _ did.DID, doc did.Document) error {
				actualDocument = doc
				// trigger validation to check if the added contact information isn't wrong
				return didnuts.ManagedDocumentValidator(nil).Validate(doc)
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
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, meta, nil)
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
	meta := &resolver.DocumentMetadata{Hash: hash.EmptyHash()}
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
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, meta, nil)
		actual, err := ctx.instance.GetContactInformation(*id)
		assert.NoError(t, err)
		assert.Equal(t, expected, *actual)
	})
	t.Run("no contact info", func(t *testing.T) {
		ctx := newMockContext(t)
		didDoc := &did.Document{}
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, meta, nil)
		actual, err := ctx.instance.GetContactInformation(*id)
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
	t.Run("error - can't resolve DID", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(nil, nil, errors.New("failed"))
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
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, meta, nil)
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
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, meta, nil)
		actual, err := ctx.instance.GetContactInformation(*id)
		assert.EqualError(t, err, "multiple contact information services found")
		assert.Nil(t, actual)
	})
}

func TestDidman_DeleteEndpointsByType(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	serviceID := did.DIDURL{DID: *id}
	serviceID.Fragment = "abc"
	endpointType := "eOverdracht"
	endpoints := []did.Service{{
		ID:              serviceID.URI(),
		Type:            endpointType,
		ServiceEndpoint: map[string]interface{}{"foo": "http://example.org"},
	}}

	meta := &resolver.DocumentMetadata{Hash: hash.EmptyHash()}
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
		ctx.didResolver.EXPECT().Resolve(*id, gomock.Any()).Return(didDoc, meta, nil).Times(2)
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
		ctx.didResolver.EXPECT().Resolve(*id, gomock.Any()).Return(didDocWithOtherService, meta, nil).Times(2)
		err := ctx.instance.DeleteEndpointsByType(ctx.audit, *id, endpointType)
		assert.NoError(t, err)
	})

	t.Run("error - unknown service type", func(t *testing.T) {
		ctx := newMockContext(t)
		// not in use by any other document
		ctx.didResolver.EXPECT().Resolve(*id, gomock.Any()).Return(didDoc, meta, nil)
		err := ctx.instance.DeleteEndpointsByType(ctx.audit, *id, "unknown type")
		assert.ErrorIs(t, err, resolver.ErrServiceNotFound)
	})

	t.Run("error - DID document", func(t *testing.T) {
		ctx := newMockContext(t)
		// not in use by any other document
		ctx.didResolver.EXPECT().Resolve(*id, gomock.Any()).Return(nil, nil, resolver.ErrNotFound)
		err := ctx.instance.DeleteEndpointsByType(ctx.audit, *id, endpointType)
		assert.ErrorIs(t, err, resolver.ErrNotFound)
	})

	t.Run("error - in use by other services", func(t *testing.T) {
		endpointsWithSelfReference := []did.Service{
			endpoints[0],
			{
				ID:              ssi.MustParseURI(id.String() + "#123"),
				Type:            "refType",
				ServiceEndpoint: resolver.MakeServiceReference(*id, endpointType),
			},
		}
		didDocErrServiceInUse := &did.Document{ID: *id, Service: endpointsWithSelfReference}
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(*id, gomock.Any()).Return(didDocErrServiceInUse, meta, nil).Times(2)
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
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServices(*id)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("ok - it ignores contact info", func(t *testing.T) {
		ctx := newMockContext(t)
		didDoc := &did.Document{Service: append(expected, did.Service{Type: ContactInformationServiceType, ServiceEndpoint: map[string]interface{}{}})}
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServices(*id)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("ok - it ignores endpoint services", func(t *testing.T) {
		ctx := newMockContext(t)
		didDoc := &did.Document{Service: append(expected, did.Service{Type: "normal-service", ServiceEndpoint: "http://api.example.com/fhir"})}
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServices(*id)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("error - unknown DID", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(nil, nil, resolver.ErrNotFound)
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

		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csType", "eType", true)
		assert.NoError(t, err)
		assert.Equal(t, expectedURL, actual)
	})
	t.Run("ok - no references", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csTypeNoRefs", "eType", true)
		assert.NoError(t, err)
		assert.Equal(t, expectedURL, actual)
	})
	t.Run("ok - resolve references - top level is compound service", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csType", "eType", false)
		assert.NoError(t, err)
		assert.Equal(t, expectedRef, actual)
	})
	t.Run("ok - resolve references - top level is reference", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csRefType", "eType", false)
		assert.NoError(t, err)
		assert.Equal(t, expectedRef, actual)
	})
	t.Run("error - unknown DID", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(nil, nil, resolver.ErrNotFound)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csType", "eType", false)
		assert.ErrorIs(t, err, resolver.ErrNotFound)
		assert.Empty(t, actual)
	})
	t.Run("error - unknown compound service", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "non-existent", "eType", false)
		assert.Contains(t, err.Error(), resolver.ErrServiceNotFound.Error())
		assert.Empty(t, actual)
	})
	t.Run("error - unknown endpoint", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csType", "non-existent", false)
		assert.ErrorIs(t, err, resolver.ErrServiceNotFound)
		assert.Empty(t, actual)
	})
	t.Run("error - endpoint is not an URL", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.didResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
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
		ctx.didResolver.EXPECT().Resolve(saasProviderDocument.ID, nil).Return(saasProviderDocument, nil, nil)
		ctx.didResolver.EXPECT().Resolve(careProviderDocument.ID, nil).Return(careProviderDocument, nil, nil)

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
		ctx.didResolver.EXPECT().Resolve(testDIDB, nil).Return(&docWithoutService, nil, nil)

		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", nil)

		assert.NoError(t, err)
		assert.Len(t, actual, 1)
	})
	t.Run("ok - with DID service type (matches)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)
		ctx.didResolver.EXPECT().Resolve(testDIDB, nil).Return(&docWithService, nil, nil)

		serviceType := "eOverdracht"
		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", &serviceType)

		assert.NoError(t, err)
		assert.Len(t, actual, 1)
	})
	t.Run("ok - with DID service type (no match)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)
		ctx.didResolver.EXPECT().Resolve(testDIDB, nil).Return(&docWithoutService, nil, nil)

		serviceType := "eOverdracht"
		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", &serviceType)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Empty(t, actual)
	})
	t.Run("ok - DID document not found (omits result)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)
		ctx.didResolver.EXPECT().Resolve(testDIDB, nil).Return(nil, nil, resolver.ErrNotFound)

		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", nil)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Empty(t, actual)
	})
	t.Run("ok - DID document deactivated (omits result)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)
		ctx.didResolver.EXPECT().Resolve(testDIDB, nil).Return(nil, nil, resolver.ErrDeactivated)

		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", nil)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Empty(t, actual)
	})
	t.Run("ok - invalid subject ID (omits result)", func(t *testing.T) {
		ctx := newMockContext(t)
		credentialWithInvalidSubjectID := vc.VerifiableCredential{}
		_ = json.Unmarshal([]byte(jsonld.TestOrganizationCredential), &credentialWithInvalidSubjectID)
		credentialWithInvalidSubjectID.CredentialSubject = []interface{}{
			map[string]interface{}{
				"id": "90",
			},
		}

		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{credentialWithInvalidSubjectID}, nil)

		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", nil)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Empty(t, actual)
	})
	t.Run("ok - missing subject ID (omits result)", func(t *testing.T) {
		ctx := newMockContext(t)
		credentialWithoutSubjectID := vc.VerifiableCredential{}
		_ = json.Unmarshal([]byte(jsonld.TestOrganizationCredential), &credentialWithoutSubjectID)
		credentialWithoutSubjectID.CredentialSubject = []interface{}{
			map[string]interface{}{},
		}

		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{credentialWithoutSubjectID}, nil)

		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", nil)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Empty(t, actual)
	})
	t.Run("ok - no subject (omits result)", func(t *testing.T) {
		ctx := newMockContext(t)
		credentialWithoutSubjectID := vc.VerifiableCredential{}
		_ = json.Unmarshal([]byte(jsonld.TestOrganizationCredential), &credentialWithoutSubjectID)
		credentialWithoutSubjectID.CredentialSubject = nil

		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{credentialWithoutSubjectID}, nil)

		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", nil)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Empty(t, actual)
	})
	t.Run("ok - other error while resolving DID document (just logged)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search(reqCtx, searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)
		ctx.didResolver.EXPECT().Resolve(testDIDB, nil).Return(nil, nil, io.EOF)

		actual, err := ctx.instance.SearchOrganizations(reqCtx, "query", nil)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
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

func TestReferencedService(t *testing.T) {
	trueDID := did.MustParseDID("did:nuts:123")
	falseDID := did.MustParseDID("did:nuts:abc")
	serviceType := "RefType"
	serviceRef := resolver.MakeServiceReference(trueDID, serviceType).String()
	compoundDocStr := `{"service":[{"id":"did:nuts:123#1","serviceEndpoint":{"nested":"%s/serviceEndpoint?type=RefType"},"type":"OtherType"}]}`
	endpointDocStr := `{"service":[{"id":"did:nuts:123#1","serviceEndpoint":"%s/serviceEndpoint?type=RefType","type":"OtherType"}]}`
	didDoc := &did.Document{}

	t.Run("false - compound service", func(t *testing.T) {
		json.Unmarshal([]byte(fmt.Sprintf(compoundDocStr, falseDID.String())), didDoc)
		assert.False(t, referencedService(didDoc, serviceRef))
	})

	t.Run("false - endpoint", func(t *testing.T) {
		json.Unmarshal([]byte(fmt.Sprintf(endpointDocStr, falseDID.String())), didDoc)
		assert.False(t, referencedService(didDoc, serviceRef))
	})

	t.Run("true - compound service", func(t *testing.T) {
		json.Unmarshal([]byte(fmt.Sprintf(compoundDocStr, trueDID.String())), didDoc)
		assert.True(t, referencedService(didDoc, serviceRef))
	})

	t.Run("true - endpoint", func(t *testing.T) {
		json.Unmarshal([]byte(fmt.Sprintf(endpointDocStr, trueDID.String())), didDoc)
		assert.True(t, referencedService(didDoc, serviceRef))
	})
}

type mockContext struct {
	ctrl        *gomock.Controller
	vdr         *vdr.MockVDR
	vcr         *vcr.MockFinder
	didResolver *resolver.MockDIDResolver
	instance    Didman
	audit       context.Context
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	didResolver := resolver.NewMockDIDResolver(ctrl)
	mockVDR := vdr.NewMockVDR(ctrl)
	mockVDR.EXPECT().Resolver().Return(didResolver).AnyTimes()
	mockVCR := vcr.NewMockFinder(ctrl)
	instance := NewDidmanInstance(mockVDR, mockVCR, jsonld.NewTestJSONLDManager(t)).(*didman)

	return mockContext{
		ctrl:        ctrl,
		didResolver: didResolver,
		vdr:         mockVDR,
		vcr:         mockVCR,
		instance:    instance,
		audit:       audit.TestContext(),
	}
}
