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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
)

func TestDidman_Name(t *testing.T) {
	instance := NewDidmanInstance(nil, nil, nil, nil).(core.Named)

	assert.Equal(t, ModuleName, instance.Name())
}

func TestNewDidmanInstance(t *testing.T) {
	ctx := newMockContext(t)
	instance := NewDidmanInstance(ctx.docResolver, ctx.store, ctx.vdr, ctx.vcr).(*didman)

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
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, nil).Return(doc, meta, nil)
		ctx.vdr.EXPECT().Update(*vdr.TestDIDA, meta.Hash, gomock.Any(), nil).DoAndReturn(
			func(_ interface{}, _ interface{}, doc interface{}, _ interface{}) error {
				newDoc = doc.(did.Document)
				return nil
			})

		ep, err := ctx.instance.AddEndpoint(*vdr.TestDIDA, "type", *u)

		if !assert.NoError(t, err) {
			return
		}
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
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, nil).Return(doc, meta, nil)
		ctx.vdr.EXPECT().Update(*vdr.TestDIDA, meta.Hash, gomock.Any(), nil).Return(returnError)

		_, err := ctx.instance.AddEndpoint(*vdr.TestDIDA, "type", *u)

		assert.Equal(t, returnError, err)
	})

	t.Run("error - duplicate service", func(t *testing.T) {
		ctx := newMockContext(t)
		doc := &did.Document{}
		returnError := errors.New("b00m!")
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, nil).Return(doc, meta, nil).Times(2)
		ctx.vdr.EXPECT().Update(*vdr.TestDIDA, meta.Hash, gomock.Any(), nil).Return(returnError)

		_, _ = ctx.instance.AddEndpoint(*vdr.TestDIDA, "type", *u)
		_, err := ctx.instance.AddEndpoint(*vdr.TestDIDA, "type", *u)

		assert.Equal(t, types.ErrDuplicateService, err)
	})

	t.Run("error - DID not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, nil).Return(nil, nil, types.ErrNotFound)

		_, err := ctx.instance.AddEndpoint(*vdr.TestDIDA, "type", *u)

		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, types.ErrNotFound, err)
	})
}

func TestDidman_AddCompoundService(t *testing.T) {
	meta := &types.DocumentMetadata{Hash: hash.EmptyHash()}

	helloServiceQuery, _ := ssi.ParseURI(vdr.TestDIDA.String() + "/serviceEndpoint?type=hello")
	worldServiceQuery, _ := ssi.ParseURI(vdr.TestDIDB.String() + "/serviceEndpoint?type=world")
	universeServiceQuery, _ := ssi.ParseURI(vdr.TestDIDB.String() + "/serviceEndpoint?type=universe")
	universeNestedServiceQuery, _ := ssi.ParseURI(vdr.TestDIDB.String() + "/serviceEndpoint?type=universe-ref")
	cyclicServiceQuery, _ := ssi.ParseURI(vdr.TestDIDB.String() + "/serviceEndpoint?type=cyclic-ref")
	references := make(map[string]ssi.URI, 0)
	references["hello"] = *helloServiceQuery
	references["world"] = *worldServiceQuery
	references["universe"] = *universeServiceQuery

	expectedRefs := map[string]interface{}{}
	for k, v := range references {
		expectedRefs[k] = v.String()
	}

	serviceID, _ := ssi.ParseURI(fmt.Sprintf("%s#1", vdr.TestDIDA.String()))
	docA := did.Document{
		Context: []ssi.URI{did.DIDContextV1URI()},
		ID:      *vdr.TestDIDA,
		Service: []did.Service{{
			ID:              *serviceID,
			Type:            "hello",
			ServiceEndpoint: "http://hello",
		}},
	}
	docB := did.Document{
		Context: []ssi.URI{did.DIDContextV1URI()},
		ID:      *vdr.TestDIDB,
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
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, nil).MinTimes(1).Return(&docA, meta, nil)
		// DID B should be resolved once, since they're cached
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDB, nil).Return(&docB, meta, nil)
		ctx.vdr.EXPECT().Update(*vdr.TestDIDA, meta.Hash, gomock.Any(), nil).DoAndReturn(
			func(_ interface{}, _ interface{}, doc interface{}, _ interface{}) error {
				newDoc = doc.(did.Document)
				// trigger validation to check if the added contact information isn't wrong
				return vdr.CreateDocumentValidator().Validate(newDoc)
			})

		_, err := ctx.instance.AddCompoundService(*vdr.TestDIDA, "helloworld", references)

		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, newDoc.Service, 2)
		assert.Equal(t, "helloworld", newDoc.Service[1].Type)
		assert.Equal(t, expectedRefs, newDoc.Service[1].ServiceEndpoint)
	})
	t.Run("ok - nested reference", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDB, nil).MinTimes(1).Return(&docB, meta, nil)
		ctx.vdr.EXPECT().Update(*vdr.TestDIDB, meta.Hash, gomock.Any(), nil)

		_, err := ctx.instance.AddCompoundService(*vdr.TestDIDB, "helloworld", map[string]ssi.URI{"foobar": *universeNestedServiceQuery})

		assert.NoError(t, err)
	})
	t.Run("ok - endpoint is an absolute URL", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, nil).MinTimes(1).Return(&docA, meta, nil)
		ctx.vdr.EXPECT().Update(*vdr.TestDIDA, meta.Hash, gomock.Any(), nil)

		s, _ := ssi.ParseURI("http://nuts.nl")
		_, err := ctx.instance.AddCompoundService(*vdr.TestDIDA, "hellonuts", map[string]ssi.URI{"foobar": *s})

		assert.NoError(t, err)
	})
	t.Run("error - cyclic reference (yields refs too deep)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDB, nil).MinTimes(1).Return(&docB, meta, nil)

		_, err := ctx.instance.AddCompoundService(*vdr.TestDIDA, "hellonuts", map[string]ssi.URI{"foobar": *cyclicServiceQuery})

		assert.ErrorIs(t, err.(ErrReferencedServiceNotAnEndpoint).Cause, ErrServiceReferenceToDeep)
	})
	t.Run("error - holder DID document can't be resolved", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, nil).Return(nil, nil, types.ErrNotFound)
		_, err := ctx.instance.AddCompoundService(*vdr.TestDIDA, "helloworld", map[string]ssi.URI{"foobar": *helloServiceQuery})
		assert.ErrorIs(t, err.(ErrReferencedServiceNotAnEndpoint).Cause, types.ErrNotFound)
	})
	t.Run("error - service reference does not contain type", func(t *testing.T) {
		ctx := newMockContext(t)
		invalidQuery := *helloServiceQuery
		invalidQuery.RawQuery = ""
		_, err := ctx.instance.AddCompoundService(*vdr.TestDIDA, "helloworld", map[string]ssi.URI{"hello": invalidQuery})
		assert.ErrorIs(t, err.(ErrReferencedServiceNotAnEndpoint).Cause, ErrInvalidServiceQuery)
	})
}

func TestDidman_validateServiceReference(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ref, _ := ssi.ParseURI("did:nuts:abc/serviceEndpoint?type=t")
		err := validateServiceReference(*ref)
		assert.NoError(t, err)
	})
	t.Run("error - invalid path", func(t *testing.T) {
		ref, _ := ssi.ParseURI("did:nuts:abc/serviceEndpointWithInvalidPostfix?type=sajdklsad")
		err := validateServiceReference(*ref)
		assert.ErrorIs(t, err, ErrInvalidServiceQuery)
	})
	t.Run("error - too many type params", func(t *testing.T) {
		ref, _ := ssi.ParseURI("did:nuts:abc/serviceEndpoint?type=t1&type=t2")
		err := validateServiceReference(*ref)
		assert.ErrorIs(t, err, ErrInvalidServiceQuery)
	})
	t.Run("error - no type params", func(t *testing.T) {
		ref, _ := ssi.ParseURI("did:nuts:abc/serviceEndpoint")
		err := validateServiceReference(*ref)
		assert.ErrorIs(t, err, ErrInvalidServiceQuery)
	})
	t.Run("error - invalid params", func(t *testing.T) {
		ref, _ := ssi.ParseURI("did:nuts:abc/serviceEndpoint?type=t1&someOther=not-allowed")
		err := validateServiceReference(*ref)
		assert.ErrorIs(t, err, ErrInvalidServiceQuery)
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
	uri, _ := ssi.ParseURI("did:nuts:123#1")
	meta := &types.DocumentMetadata{Hash: hash.EmptyHash()}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		var newDoc did.Document
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(doc(), meta, nil)
		ctx.store.EXPECT().Iterate(gomock.Any()).Return(nil)
		ctx.vdr.EXPECT().Update(*id, meta.Hash, gomock.Any(), nil).DoAndReturn(
			func(_ interface{}, _ interface{}, doc interface{}, _ interface{}) error {
				newDoc = doc.(did.Document)
				return nil
			})

		err := ctx.instance.DeleteService(*uri)

		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, newDoc.Service, 0)
	})

	t.Run("error - service not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(doc(), meta, nil)
		ctx.store.EXPECT().Iterate(gomock.Any()).Return(nil)
		nonExistingID := *uri
		nonExistingID.Fragment = "non-existent"

		err := ctx.instance.DeleteService(nonExistingID)

		assert.Equal(t, ErrServiceNotFound, err)
	})

	t.Run("error - in use", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(doc(), meta, nil)
		ctx.store.EXPECT().Iterate(gomock.Any()).Return(ErrServiceInUse)

		err := ctx.instance.DeleteService(*uri)

		assert.Equal(t, ErrServiceInUse, err)
	})

	t.Run("error - update failed", func(t *testing.T) {
		ctx := newMockContext(t)
		returnError := errors.New("b00m!")
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(doc(), meta, nil)
		ctx.store.EXPECT().Iterate(gomock.Any()).Return(nil)
		ctx.vdr.EXPECT().Update(*id, meta.Hash, gomock.Any(), nil).Return(returnError)

		err := ctx.instance.DeleteService(*uri)

		assert.Equal(t, returnError, err)
	})

	t.Run("error - DID not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(nil, nil, types.ErrNotFound)

		err := ctx.instance.DeleteService(*uri)

		assert.Equal(t, types.ErrNotFound, err)
	})
}

func TestDidman_UpdateContactInformation(t *testing.T) {
	didDoc := doc.CreateDocument()
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
		ctx.vdr.EXPECT().Update(*id, meta.Hash, gomock.Any(), nil).DoAndReturn(func(_ did.DID, _ hash.SHA256Hash, doc did.Document, _ *types.DocumentMetadata) error {
			actualDocument = doc
			// trigger validation to check if the added contact information isn't wrong
			return vdr.CreateDocumentValidator().Validate(doc)
		})
		actual, err := ctx.instance.UpdateContactInformation(*id, expected)
		if !assert.NoError(t, err) {
			return
		}
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
		ctx.vdr.EXPECT().Update(*id, meta.Hash, gomock.Any(), nil).Do(func(_ did.DID, _ hash.SHA256Hash, doc did.Document, _ *types.DocumentMetadata) {
			actualDocument = doc
		})
		actual, err := ctx.instance.UpdateContactInformation(*id, expected)
		if !assert.NoError(t, err) {
			return
		}
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
		ctx.vdr.EXPECT().Update(*id, meta.Hash, gomock.Any(), nil).DoAndReturn(
			func(_ interface{}, _ interface{}, doc did.Document, _ interface{}) error {
				assert.Len(t, doc.Service, 0)
				return nil
			})
		// not in use by any other document
		ctx.store.EXPECT().Iterate(gomock.Any()).Return(nil)
		ctx.docResolver.EXPECT().Resolve(*id, gomock.Any()).Return(didDoc, meta, nil).Times(2)
		err := ctx.instance.DeleteEndpointsByType(*id, endpointType)
		assert.NoError(t, err)
	})

	t.Run("ok - it keeps other services", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vdr.EXPECT().Update(*id, meta.Hash, gomock.Any(), nil).DoAndReturn(
			func(_ interface{}, _ interface{}, doc did.Document, _ interface{}) error {
				assert.Len(t, doc.Service, 1)
				return nil
			})
		otherServiceID, _ := ssi.ParseURI("did:nuts:123#def")
		otherService := did.Service{
			ID:   *otherServiceID,
			Type: "other",
		}
		didDocWithOtherService := &did.Document{ID: *id, Service: append(endpoints, otherService)}
		// not in use by any other document
		ctx.store.EXPECT().Iterate(gomock.Any()).Return(nil)
		ctx.docResolver.EXPECT().Resolve(*id, gomock.Any()).Return(didDocWithOtherService, meta, nil).Times(2)
		err := ctx.instance.DeleteEndpointsByType(*id, endpointType)
		assert.NoError(t, err)
	})

	t.Run("error - unknown service type", func(t *testing.T) {
		ctx := newMockContext(t)
		// not in use by any other document
		ctx.docResolver.EXPECT().Resolve(*id, gomock.Any()).Return(didDoc, meta, nil)
		err := ctx.instance.DeleteEndpointsByType(*id, "unknown type")
		assert.ErrorIs(t, err, ErrServiceNotFound)
	})

	t.Run("error - DID document", func(t *testing.T) {
		ctx := newMockContext(t)
		// not in use by any other document
		ctx.docResolver.EXPECT().Resolve(*id, gomock.Any()).Return(nil, nil, types.ErrNotFound)
		err := ctx.instance.DeleteEndpointsByType(*id, endpointType)
		assert.ErrorIs(t, err, types.ErrNotFound)
	})

	t.Run("error - in use by other services", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.store.EXPECT().Iterate(gomock.Any()).Return(ErrServiceInUse)
		ctx.docResolver.EXPECT().Resolve(*id, gomock.Any()).Return(didDoc, meta, nil).Times(2)
		err := ctx.instance.DeleteEndpointsByType(*id, endpointType)
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
				"non-url": true,
			},
		},
		{
			Type:            "url",
			ServiceEndpoint: expectedURL,
		},
	}, ID: *id}
	t.Run("ok - resolve references", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csType", "eType", true)
		assert.NoError(t, err)
		assert.Equal(t, expectedURL, actual)
	})
	t.Run("ok - resolve references", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csType", "eType", false)
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
		assert.ErrorIs(t, err, ErrServiceNotFound)
		assert.Empty(t, actual)
	})
	t.Run("error - unknown endpoint", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csType", "non-existent", false)
		assert.ErrorIs(t, err, ErrServiceNotFound)
		assert.Empty(t, actual)
	})
	t.Run("error - endpoint is not an URL", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(didDoc, nil, nil)
		actual, err := ctx.instance.GetCompoundServiceEndpoint(*id, "csType", "non-url", false)
		assert.ErrorIs(t, err, ErrReferencedServiceNotAnEndpoint{})
		assert.Empty(t, actual)
	})
}

func TestDidman_SearchOrganizations(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	docWithService := did.Document{
		ID: *id,
		Service: []did.Service{{
			Type:            "eOverdracht",
			ServiceEndpoint: map[string]interface{}{"foo": "http://example.org"},
		}},
	}
	docWithoutService := did.Document{
		ID: *id,
	}
	//

	t.Run("ok - no results", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search("organization", map[string]string{"organization.name": "query"}).Return([]concept.Concept{}, nil)

		actual, err := ctx.instance.SearchOrganizations("query", nil)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Empty(t, actual)
	})
	cpt := map[string]interface{}{
		"subject":      id.String(),
		"organization": map[string]interface{}{"name": "Foo"},
	}
	t.Run("ok - no DID service type", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search("organization", map[string]string{"organization.name": "query"}).Return([]concept.Concept{cpt}, nil)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(&docWithoutService, nil, nil)

		actual, err := ctx.instance.SearchOrganizations("query", nil)

		assert.NoError(t, err)
		assert.Len(t, actual, 1)
	})
	t.Run("ok - with DID service type (matches)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search("organization", map[string]string{"organization.name": "query"}).Return([]concept.Concept{cpt}, nil)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(&docWithService, nil, nil)

		serviceType := "eOverdracht"
		actual, err := ctx.instance.SearchOrganizations("query", &serviceType)

		assert.NoError(t, err)
		assert.Len(t, actual, 1)
	})
	t.Run("ok - with DID service type (no match)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search("organization", map[string]string{"organization.name": "query"}).Return([]concept.Concept{cpt}, nil)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(&docWithoutService, nil, nil)

		serviceType := "eOverdracht"
		actual, err := ctx.instance.SearchOrganizations("query", &serviceType)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Empty(t, actual)
	})
	t.Run("ok - DID document not found (logs, omits result)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search("organization", map[string]string{"organization.name": "query"}).Return([]concept.Concept{cpt}, nil)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(nil, nil, types.ErrNotFound)

		actual, err := ctx.instance.SearchOrganizations("query", nil)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Empty(t, actual)
	})
	t.Run("ok - DID document deactivated (logs, omits result)", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search("organization", map[string]string{"organization.name": "query"}).Return([]concept.Concept{cpt}, nil)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(nil, nil, types.ErrDeactivated)

		actual, err := ctx.instance.SearchOrganizations("query", nil)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Empty(t, actual)
	})
	t.Run("error - other error while resolving DID document", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Search("organization", map[string]string{"organization.name": "query"}).Return([]concept.Concept{cpt}, nil)
		ctx.docResolver.EXPECT().Resolve(*id, nil).Return(nil, nil, io.EOF)

		actual, err := ctx.instance.SearchOrganizations("query", nil)

		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestGenerateIDForService(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/v1")
	expectedID, _ := ssi.ParseURI(fmt.Sprintf("%s#D4eNCVjdtGaeHYMdjsdYHpTQmiwXtQKJmE9QSwwsKKzy", vdr.TestDIDA.String()))

	id := generateIDForService(*vdr.TestDIDA, did.Service{
		Type:            "type",
		ServiceEndpoint: u.String(),
	})
	assert.Equal(t, *expectedID, id)
}

func TestReferencesService(t *testing.T) {
	t.Run("false", func(t *testing.T) {
		didDocStr := `{"service":[{"id":"did:nuts:1234#1", "serviceEndpoint": {"ref":"did:nuts:123#2"}}]}`
		didDoc := did.Document{}
		json.Unmarshal([]byte(didDocStr), &didDoc)
		uri, _ := ssi.ParseURI("did:nuts:123#1")

		assert.False(t, referencesService(didDoc, *uri))
	})

	t.Run("true", func(t *testing.T) {
		didDocStr := `{"service":[{"id":"did:nuts:1234#1", "serviceEndpoint": {"ref":"did:nuts:123#1"}}]}`
		didDoc := did.Document{}
		json.Unmarshal([]byte(didDocStr), &didDoc)
		uri, _ := ssi.ParseURI("did:nuts:123#1")

		assert.True(t, referencesService(didDoc, *uri))
	})
}

type mockContext struct {
	ctrl        *gomock.Controller
	docResolver *types.MockDocResolver
	store       *types.MockStore
	vdr         *types.MockVDR
	vcr         *vcr.MockVCR
	instance    Didman
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	t.Cleanup(func() {
		ctrl.Finish()
	})
	docResolver := types.NewMockDocResolver(ctrl)
	store := types.NewMockStore(ctrl)
	mockVDR := types.NewMockVDR(ctrl)
	mockVCR := vcr.NewMockVCR(ctrl)
	instance := NewDidmanInstance(docResolver, store, mockVDR, mockVCR)

	return mockContext{
		ctrl:        ctrl,
		docResolver: docResolver,
		store:       store,
		vdr:         mockVDR,
		vcr:         mockVCR,
		instance:    instance,
	}
}
