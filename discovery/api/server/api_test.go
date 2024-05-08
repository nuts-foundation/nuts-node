/*
 * Copyright (C) 2024 Nuts community
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

package server

import (
	"errors"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/discovery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"net/http"
	"testing"
)

const serviceID = "wonderland"

var subjectDID = did.MustParseDID("did:web:example.com")

func TestWrapper_GetPresentations(t *testing.T) {
	lastTimestamp := 1
	presentations := map[string]vc.VerifiablePresentation{}
	t.Run("no timestamp", func(t *testing.T) {
		test := newMockContext(t)
		test.server.EXPECT().Get(gomock.Any(), serviceID, 0).Return(presentations, lastTimestamp, nil)

		response, err := test.wrapper.GetPresentations(nil, GetPresentationsRequestObject{ServiceID: serviceID})

		require.NoError(t, err)
		require.IsType(t, GetPresentations200JSONResponse{}, response)
		assert.Equal(t, lastTimestamp, response.(GetPresentations200JSONResponse).Timestamp)
		assert.Equal(t, presentations, response.(GetPresentations200JSONResponse).Entries)
	})
	t.Run("with timestamp", func(t *testing.T) {
		givenTimestamp := 1
		test := newMockContext(t)
		test.server.EXPECT().Get(gomock.Any(), serviceID, 1).Return(presentations, lastTimestamp, nil)

		response, err := test.wrapper.GetPresentations(nil, GetPresentationsRequestObject{
			ServiceID: serviceID,
			Params: GetPresentationsParams{
				Timestamp: &givenTimestamp,
			},
		})

		require.NoError(t, err)
		require.IsType(t, GetPresentations200JSONResponse{}, response)
		assert.Equal(t, lastTimestamp, response.(GetPresentations200JSONResponse).Timestamp)
		assert.Equal(t, presentations, response.(GetPresentations200JSONResponse).Entries)
	})
	t.Run("error", func(t *testing.T) {
		test := newMockContext(t)
		test.server.EXPECT().Get(gomock.Any(), serviceID, 0).Return(nil, 0, errors.New("foo"))

		_, err := test.wrapper.GetPresentations(nil, GetPresentationsRequestObject{ServiceID: serviceID})

		assert.Error(t, err)
	})
}

func TestWrapper_RegisterPresentation(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		test := newMockContext(t)
		presentation := vc.VerifiablePresentation{}
		test.server.EXPECT().Register(gomock.Any(), serviceID, presentation).Return(nil)

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
		test.server.EXPECT().Register(gomock.Any(), serviceID, presentation).Return(discovery.ErrInvalidPresentation)

		_, err := test.wrapper.RegisterPresentation(nil, RegisterPresentationRequestObject{
			ServiceID: serviceID,
			Body:      &presentation,
		})

		assert.ErrorIs(t, err, discovery.ErrInvalidPresentation)
	})
}

func TestWrapper_ResolveStatusCode(t *testing.T) {
	expected := map[error]int{
		discovery.ErrInvalidPresentation: http.StatusBadRequest,
		errors.New("foo"):                http.StatusInternalServerError,
	}
	wrapper := Wrapper{}
	for err, expectedCode := range expected {
		t.Run(err.Error(), func(t *testing.T) {
			assert.Equal(t, expectedCode, wrapper.ResolveStatusCode(err))
		})
	}
}

type mockContext struct {
	ctrl    *gomock.Controller
	server  *discovery.MockServer
	wrapper Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	server := discovery.NewMockServer(ctrl)
	return mockContext{
		ctrl:    ctrl,
		server:  server,
		wrapper: Wrapper{Server: server},
	}
}
