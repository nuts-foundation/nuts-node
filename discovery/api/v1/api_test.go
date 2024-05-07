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

package v1

import (
	"context"
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/discovery"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"net/url"
	"testing"
)

const serviceID = "wonderland"

var subjectDID = did.MustParseDID("did:web:example.com")

func TestWrapper_ActivateServiceForDID(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		test.client.EXPECT().ActivateServiceForDID(gomock.Any(), serviceID, subjectDID).Return(nil)

		response, err := test.wrapper.ActivateServiceForDID(nil, ActivateServiceForDIDRequestObject{
			ServiceID: serviceID,
			Did:       subjectDID.String(),
		})

		assert.NoError(t, err)
		assert.IsType(t, ActivateServiceForDID200Response{}, response)
	})
	t.Run("ok, but registration failed", func(t *testing.T) {
		test := newMockContext(t)
		expectedDID := "did:web:example.com"
		test.client.EXPECT().ActivateServiceForDID(gomock.Any(), gomock.Any(), gomock.Any()).Return(discovery.ErrPresentationRegistrationFailed)

		response, err := test.wrapper.ActivateServiceForDID(nil, ActivateServiceForDIDRequestObject{
			ServiceID: serviceID,
			Did:       expectedDID,
		})

		assert.NoError(t, err)
		assert.IsType(t, ActivateServiceForDID202JSONResponse{}, response)
	})
	t.Run("other error", func(t *testing.T) {
		test := newMockContext(t)
		expectedDID := "did:web:example.com"
		test.client.EXPECT().ActivateServiceForDID(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("foo"))

		_, err := test.wrapper.ActivateServiceForDID(nil, ActivateServiceForDIDRequestObject{
			ServiceID: serviceID,
			Did:       expectedDID,
		})

		assert.Error(t, err)
	})
}

func TestWrapper_DeactivateServiceForDID(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		expectedDID := "did:web:example.com"
		test.client.EXPECT().DeactivateServiceForDID(gomock.Any(), serviceID, did.MustParseDID(expectedDID)).Return(nil)

		response, err := test.wrapper.DeactivateServiceForDID(nil, DeactivateServiceForDIDRequestObject{
			ServiceID: serviceID,
			Did:       expectedDID,
		})

		assert.NoError(t, err)
		assert.IsType(t, DeactivateServiceForDID200Response{}, response)
	})
	t.Run("error", func(t *testing.T) {
		test := newMockContext(t)
		expectedDID := "did:web:example.com"
		test.client.EXPECT().DeactivateServiceForDID(gomock.Any(), serviceID, did.MustParseDID(expectedDID)).Return(errors.New("foo"))

		_, err := test.wrapper.DeactivateServiceForDID(nil, DeactivateServiceForDIDRequestObject{
			ServiceID: serviceID,
			Did:       expectedDID,
		})

		assert.Error(t, err)
	})
}

func TestWrapper_SearchPresentations(t *testing.T) {
	ctx := context.WithValue(audit.TestContext(), requestQueryContextKey{}, url.Values{
		"foo": []string{"bar"},
	})
	expectedQuery := map[string]string{
		"foo": "bar",
	}
	id, _ := ssi.ParseURI("did:nuts:foo#1")
	vp := test.ParsePresentation(t, vc.VerifiablePresentation{
		ID:                   id,
		VerifiableCredential: []vc.VerifiableCredential{test.ValidNutsOrganizationCredential(t)},
		Proof: []interface{}{proof.LDProof{
			VerificationMethod: *id,
		}},
	})
	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		results := []discovery.SearchResult{
			{
				Presentation: vp,
				Fields:       nil,
			},
		}
		test.client.EXPECT().Search(serviceID, expectedQuery).Return(results, nil)

		response, err := test.wrapper.SearchPresentations(ctx, SearchPresentationsRequestObject{
			ServiceID: serviceID,
		})

		assert.NoError(t, err)
		assert.IsType(t, SearchPresentations200JSONResponse{}, response)
		actual := response.(SearchPresentations200JSONResponse)
		require.Len(t, actual, 1)
		assert.Equal(t, vp, actual[0].Vp)
		assert.Equal(t, vp.ID.String(), actual[0].Id)
		assert.Equal(t, "did:nuts:foo", actual[0].SubjectId)
	})
	t.Run("no results", func(t *testing.T) {
		test := newMockContext(t)
		test.client.EXPECT().Search(serviceID, expectedQuery).Return(nil, nil)

		response, err := test.wrapper.SearchPresentations(ctx, SearchPresentationsRequestObject{
			ServiceID: serviceID,
		})

		assert.NoError(t, err)
		assert.IsType(t, SearchPresentations200JSONResponse{}, response)
		actual := response.(SearchPresentations200JSONResponse)
		assert.NotNil(t, []SearchResult(actual))
		assert.Len(t, actual, 0)
	})
	t.Run("error", func(t *testing.T) {
		test := newMockContext(t)
		test.client.EXPECT().Search(serviceID, expectedQuery).Return(nil, discovery.ErrServiceNotFound)

		_, err := test.wrapper.SearchPresentations(ctx, SearchPresentationsRequestObject{
			ServiceID: serviceID,
		})

		assert.ErrorIs(t, err, discovery.ErrServiceNotFound)
	})
}

func TestWrapper_GetServiceActivation(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		test.client.EXPECT().GetServiceActivation(gomock.Any(), serviceID, subjectDID).Return(true, nil, nil)

		response, err := test.wrapper.GetServiceActivation(nil, GetServiceActivationRequestObject{
			Did:       subjectDID.String(),
			ServiceID: serviceID,
		})

		assert.NoError(t, err)
		require.IsType(t, GetServiceActivation200JSONResponse{}, response)
		assert.True(t, response.(GetServiceActivation200JSONResponse).Activated)
		assert.Nil(t, response.(GetServiceActivation200JSONResponse).Vp)
	})
	t.Run("error", func(t *testing.T) {
		test := newMockContext(t)
		test.client.EXPECT().GetServiceActivation(gomock.Any(), serviceID, subjectDID).Return(false, nil, assert.AnError)

		_, err := test.wrapper.GetServiceActivation(nil, GetServiceActivationRequestObject{
			Did:       subjectDID.String(),
			ServiceID: serviceID,
		})

		assert.Error(t, err)
	})
}

type mockContext struct {
	ctrl    *gomock.Controller
	client  *discovery.MockClient
	wrapper Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	client := discovery.NewMockClient(ctrl)
	return mockContext{
		ctrl:    ctrl,
		client:  client,
		wrapper: Wrapper{Client: client},
	}
}
