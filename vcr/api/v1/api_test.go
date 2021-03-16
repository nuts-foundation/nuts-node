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
	"fmt"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	did2 "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr/types"
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

	t.Run("error - DID not found", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any())
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())
		ctx.vcr.EXPECT().Issue(gomock.Any()).Return(nil, fmt.Errorf("wrapped error: %w", types.ErrNotFound))

		err := ctx.client.Create(ctx.echo)

		assert.NoError(t, err)
	})

	t.Run("error - key not found", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any())
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())
		ctx.vcr.EXPECT().Issue(gomock.Any()).Return(nil, fmt.Errorf("wrapped error: %w", types.ErrKeyNotFound))

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

		var resolutionResult ResolutionResult
		ctx.vcr.EXPECT().Resolve(*id).Return(&vc, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			resolutionResult = f2.(ResolutionResult)
			return nil
		})

		err := ctx.client.Resolve(ctx.echo, idString)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, id, resolutionResult.VerifiableCredential.ID)
		assert.Equal(t, trusted, resolutionResult.CurrentStatus)
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vcr.EXPECT().Resolve(*id).Return(nil, vcr.ErrNotFound)
		ctx.echo.EXPECT().NoContent(http.StatusNotFound).Return(nil)

		err := ctx.client.Resolve(ctx.echo, idString)

		assert.NoError(t, err)
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vcr.EXPECT().Resolve(*id).Return(nil, errors.New("b00m!"))

		err := ctx.client.Resolve(ctx.echo, idString)

		assert.Error(t, err)
	})

	t.Run("error - revoked", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		var resolutionResult ResolutionResult
		ctx.vcr.EXPECT().Resolve(*id).Return(&vc, vcr.ErrRevoked)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			resolutionResult = f2.(ResolutionResult)
			return nil
		})

		err := ctx.client.Resolve(ctx.echo, idString)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, id, resolutionResult.VerifiableCredential.ID)
		assert.Equal(t, revoked, resolutionResult.CurrentStatus)
	})

	t.Run("error - revoked", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		var resolutionResult ResolutionResult
		ctx.vcr.EXPECT().Resolve(*id).Return(&vc, vcr.ErrUntrusted)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			resolutionResult = f2.(ResolutionResult)
			return nil
		})

		err := ctx.client.Resolve(ctx.echo, idString)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, id, resolutionResult.VerifiableCredential.ID)
		assert.Equal(t, untrusted, resolutionResult.CurrentStatus)
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

		err := ctx.client.Search(ctx.echo, "human")

		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, capturedConcept, 1)
		assert.Equal(t, "did:nuts:1#123", capturedConcept[0]["id"])
		assert.Equal(t, "HumanCredential", capturedConcept[0]["type"])
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

		err := ctx.client.Search(ctx.echo, "human")

		assert.Error(t, err)
	})
}

func TestWrapper_Revoke(t *testing.T) {
	revocation := &credential.Revocation{}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vcr.EXPECT().Revoke(gomock.Any()).Return(revocation, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, revocation)

		err := ctx.client.Revoke(ctx.echo, "test")

		assert.NoError(t, err)
	})

	t.Run("error - bad ID", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())

		err := ctx.client.Revoke(ctx.echo, string([]byte{0}))

		assert.NoError(t, err)
	})

	t.Run("error - already revoked", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vcr.EXPECT().Revoke(gomock.Any()).Return(nil, vcr.ErrRevoked)
		ctx.echo.EXPECT().NoContent(http.StatusConflict)

		err := ctx.client.Revoke(ctx.echo, "test")

		assert.NoError(t, err)
	})

	t.Run("err - not found", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vcr.EXPECT().Revoke(gomock.Any()).Return(nil, vcr.ErrNotFound)
		ctx.echo.EXPECT().NoContent(http.StatusNotFound)

		err := ctx.client.Revoke(ctx.echo, "test")

		assert.NoError(t, err)
	})

	t.Run("err - not issuer", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vcr.EXPECT().Revoke(gomock.Any()).Return(nil, types.ErrKeyNotFound)
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())

		err := ctx.client.Revoke(ctx.echo, "test")

		assert.NoError(t, err)
	})

	t.Run("err - other", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vcr.EXPECT().Revoke(gomock.Any()).Return(nil, errors.New("b00m!"))

		err := ctx.client.Revoke(ctx.echo, "test")

		assert.Error(t, err)
	})
}

func TestWrapper_TrustUntrust(t *testing.T) {
	vc := concept.TestVC()
	issuer := vc.Issuer
	cType := vc.Type[0]

	t.Run("ok - add", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			capturedCombination := f.(*CredentialIssuer)
			capturedCombination.CredentialType = cType.String()
			capturedCombination.Issuer = issuer.String()
			return nil
		})
		ctx.vcr.EXPECT().Trust(cType, issuer).Return(nil)
		ctx.echo.EXPECT().NoContent(http.StatusAccepted)

		ctx.client.TrustIssuer(ctx.echo)
	})

	t.Run("ok - remove", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			capturedCombination := f.(*CredentialIssuer)
			capturedCombination.CredentialType = cType.String()
			capturedCombination.Issuer = issuer.String()
			return nil
		})
		ctx.vcr.EXPECT().Untrust(cType, issuer).Return(nil)
		ctx.echo.EXPECT().NoContent(http.StatusAccepted)

		ctx.client.UntrustIssuer(ctx.echo)
	})

	t.Run("error - invalid issuer", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			capturedCombination := f.(*CredentialIssuer)
			capturedCombination.CredentialType = cType.String()
			capturedCombination.Issuer = string([]byte{0})
			return nil
		})
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())

		ctx.client.TrustIssuer(ctx.echo)
	})

	t.Run("error - invalid credential", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			capturedCombination := f.(*CredentialIssuer)
			capturedCombination.CredentialType = string([]byte{0})
			capturedCombination.Issuer = cType.String()
			return nil
		})
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())

		ctx.client.TrustIssuer(ctx.echo)
	})

	t.Run("error - invalid body", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			return errors.New("b00m!")
		})
		ctx.echo.EXPECT().String(http.StatusBadRequest, gomock.Any())

		ctx.client.TrustIssuer(ctx.echo)
	})

	t.Run("error - failed to add", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			capturedCombination := f.(*CredentialIssuer)
			capturedCombination.CredentialType = cType.String()
			capturedCombination.Issuer = issuer.String()
			return nil
		})
		ctx.vcr.EXPECT().Trust(cType, issuer).Return(errors.New("b00m!"))

		err := ctx.client.TrustIssuer(ctx.echo)

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
