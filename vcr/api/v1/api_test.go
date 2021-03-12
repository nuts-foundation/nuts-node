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
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	did2 "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/stretchr/testify/assert"
)

func TestWrapper_CreateDID(t *testing.T) {
	issuer, _ := did2.ParseURI("did:nuts:1")

	vc := did2.VerifiableCredential{
		Issuer: *issuer,
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		var vcReturn *did2.VerifiableCredential
		ctx.echo.EXPECT().Bind(gomock.Any())
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			vcReturn = f2.(*did2.VerifiableCredential)
			return nil
		})
		ctx.vcr.EXPECT().Issue(gomock.Any()).Return(&vc, nil)
		err := ctx.client.Create(ctx.echo)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, *issuer, vcReturn.Issuer)
	})

	t.Run("error - parse error", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())

		err := ctx.client.Create(ctx.echo)

		if !assert.NoError(t, err) {
			return
		}
	})

	t.Run("error - issue error", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any())
		ctx.vcr.EXPECT().Issue(gomock.Any()).Return(nil, errors.New("b00m!"))

		err := ctx.client.Create(ctx.echo)

		assert.Error(t, err)
	})

	t.Run("error - validation error", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any())
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())
		ctx.vcr.EXPECT().Issue(gomock.Any()).Return(nil, credential.ErrValidation)

		err := ctx.client.Create(ctx.echo)

		assert.NoError(t, err)
	})
}

func TestWrapper_Resolve(t *testing.T) {
	idString := "did:nuts:1#1"
	id, _ := did2.ParseURI(idString)

	vc := did2.VerifiableCredential{
		ID: id,
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		var vcReturn did2.VerifiableCredential
		ctx.vcr.EXPECT().Resolve(idString).Return(vc, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			vcReturn = f2.(did2.VerifiableCredential)
			return nil
		})

		err := ctx.client.Resolve(ctx.echo, idString)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, id, vcReturn.ID)
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vcr.EXPECT().Resolve(idString).Return(vc, vcr.ErrNotFound)
		ctx.echo.EXPECT().NoContent(http.StatusNotFound).Return(nil)

		err := ctx.client.Resolve(ctx.echo, idString)

		assert.NoError(t, err)
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vcr.EXPECT().Resolve(idString).Return(vc, errors.New("b00m!"))

		err := ctx.client.Resolve(ctx.echo, idString)

		assert.Error(t, err)
	})
}

func TestWrapper_Search(t *testing.T) {
	searchRequest := SearchRequest{
		Params: []KeyValuePair{
			{
				Key:   "name",
				Value: "Because we care B.V.",
			},
		},
	}
	registry := concept.NewRegistry()
	template, _ := concept.ParseTemplate(concept.ExampleTemplate)
	registry.Add(template)

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.client.CR = registry
		defer ctx.ctrl.Finish()

		var capturedConcept []concept.Concept
		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			sr := f.(*SearchRequest)
			*sr = searchRequest
			return nil
		})
		ctx.vcr.EXPECT().Search(gomock.Any()).Return([]did2.VerifiableCredential{concept.TestVC()}, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			capturedConcept = f2.([]concept.Concept)
			return nil
		})

		err := ctx.client.Search(ctx.echo, "organization")

		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, capturedConcept, 1)
		assert.Equal(t, "did:nuts:1#123", capturedConcept[0]["id"])
		assert.Equal(t, "ExampleCredential", capturedConcept[0]["type"])
	})

	t.Run("error - unknown template", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.client.CR = registry
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any())
		ctx.echo.EXPECT().NoContent(http.StatusNotFound).Return(nil)

		err := ctx.client.Search(ctx.echo, "unknown")

		assert.NoError(t, err)
	})

	t.Run("error - Bind explodes", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any()).Return(nil)

		err := ctx.client.Search(ctx.echo, "unknown")

		assert.NoError(t, err)
	})

	t.Run("error - search returns error", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.client.CR = registry
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any())
		ctx.vcr.EXPECT().Search(gomock.Any()).Return(nil, errors.New("b00m!"))

		err := ctx.client.Search(ctx.echo, "organization")

		assert.Error(t, err)
	})
}

type mockContext struct {
	ctrl     *gomock.Controller
	echo     *mock.MockContext
	registry *concept.MockRegistry
	vcr      *vcr.MockVCR
	client   *Wrapper
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	registry := concept.NewMockRegistry(ctrl)
	vcr := vcr.NewMockVCR(ctrl)
	client := &Wrapper{CR: registry, R: vcr}

	return mockContext{
		ctrl:     ctrl,
		echo:     mock.NewMockContext(ctrl),
		registry: registry,
		vcr:      vcr,
		client:   client,
	}
}
