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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/discovery"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
)

const serviceID = "wonderland"

func TestWrapper_GetPresentations(t *testing.T) {
	t.Run("no tag", func(t *testing.T) {
		latestTag := discovery.Tag("latest")
		test := newMockContext(t)
		presentations := []vc.VerifiablePresentation{}
		test.server.EXPECT().Get(serviceID, nil).Return(presentations, &latestTag, nil)

		response, err := test.wrapper.GetPresentations(nil, GetPresentationsRequestObject{ServiceID: serviceID})

		require.NoError(t, err)
		require.IsType(t, GetPresentations200JSONResponse{}, response)
		assert.Equal(t, latestTag, discovery.Tag(response.(GetPresentations200JSONResponse).Tag))
		assert.Equal(t, presentations, response.(GetPresentations200JSONResponse).Entries)
	})
	t.Run("with tag", func(t *testing.T) {
		givenTag := discovery.Tag("given")
		latestTag := discovery.Tag("latest")
		test := newMockContext(t)
		presentations := []vc.VerifiablePresentation{}
		test.server.EXPECT().Get(serviceID, &givenTag).Return(presentations, &latestTag, nil)

		response, err := test.wrapper.GetPresentations(nil, GetPresentationsRequestObject{
			ServiceID: serviceID,
			Params: GetPresentationsParams{
				Tag: (*string)(&givenTag),
			},
		})

		require.NoError(t, err)
		require.IsType(t, GetPresentations200JSONResponse{}, response)
		assert.Equal(t, latestTag, discovery.Tag(response.(GetPresentations200JSONResponse).Tag))
		assert.Equal(t, presentations, response.(GetPresentations200JSONResponse).Entries)
	})
}

func TestWrapper_RegisterPresentation(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		presentation := vc.VerifiablePresentation{}
		test.server.EXPECT().Add(serviceID, presentation).Return(nil)

		response, err := test.wrapper.RegisterPresentation(nil, RegisterPresentationRequestObject{
			ServiceID: serviceID,
			Body:      &presentation,
		})

		assert.NoError(t, err)
		assert.IsType(t, RegisterPresentation201Response{}, response)
	})
	t.Run("error", func(t *testing.T) {
		test := newMockContext(t)
		presentation := vc.VerifiablePresentation{}
		test.server.EXPECT().Add(serviceID, presentation).Return(discovery.ErrInvalidPresentation)

		_, err := test.wrapper.RegisterPresentation(nil, RegisterPresentationRequestObject{
			ServiceID: serviceID,
			Body:      &presentation,
		})

		assert.ErrorIs(t, err, discovery.ErrInvalidPresentation)
	})
}

func TestWrapper_SearchPresentations(t *testing.T) {
	query := map[string]string{
		"foo": "bar",
	}
	id, _ := ssi.ParseURI("did:nuts:foo#1")
	vp := vc.VerifiablePresentation{
		ID:                   id,
		VerifiableCredential: []vc.VerifiableCredential{credential.ValidNutsOrganizationCredential(t)},
	}
	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		results := []discovery.SearchResult{
			{
				VP:     vp,
				Fields: nil,
			},
		}
		test.client.EXPECT().Search(serviceID, query).Return(results, nil)

		response, err := test.wrapper.SearchPresentations(nil, SearchPresentationsRequestObject{
			ServiceID: serviceID,
			Params:    SearchPresentationsParams{Query: query},
		})

		assert.NoError(t, err)
		assert.IsType(t, SearchPresentations200JSONResponse{}, response)
		actual := response.(SearchPresentations200JSONResponse)
		require.Len(t, actual, 1)
		assert.Equal(t, vp, actual[0].Vp)
		assert.Equal(t, vp.ID.String(), actual[0].Id)
	})
	t.Run("error", func(t *testing.T) {
		test := newMockContext(t)
		test.client.EXPECT().Search(serviceID, query).Return(nil, discovery.ErrServiceNotFound)

		_, err := test.wrapper.SearchPresentations(nil, SearchPresentationsRequestObject{
			ServiceID: serviceID,
			Params:    SearchPresentationsParams{Query: query},
		})

		assert.ErrorIs(t, err, discovery.ErrServiceNotFound)
	})
}

type mockContext struct {
	ctrl    *gomock.Controller
	server  *discovery.MockServer
	client  *discovery.MockClient
	wrapper Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	server := discovery.NewMockServer(ctrl)
	client := discovery.NewMockClient(ctrl)
	return mockContext{
		ctrl:    ctrl,
		server:  server,
		client:  client,
		wrapper: Wrapper{Server: server, Client: client},
	}
}
