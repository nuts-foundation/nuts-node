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
	"time"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vdr"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/stretchr/testify/assert"
)

func TestWrapper_Preprocess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	w := &Wrapper{}
	ctx := mock.NewMockContext(ctrl)
	ctx.EXPECT().Set(core.StatusCodeResolverContextKey, w)
	ctx.EXPECT().Set(core.OperationIDContextKey, "foo")
	ctx.EXPECT().Set(core.ModuleNameContextKey, "VCR")

	w.Preprocess("foo", ctx)
}

func Test_ErrorStatusCodes(t *testing.T) {
	assert.NotNil(t, (&Wrapper{}).ResolveStatusCode(nil))
}

func TestWrapper_CreateDID(t *testing.T) {
	issuer := vdr.TestDIDA.URI()

	v := vc.VerifiableCredential{
		Issuer: issuer,
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		var vcReturn *vc.VerifiableCredential
		ctx.echo.EXPECT().Bind(gomock.Any())
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			vcReturn = f2.(*vc.VerifiableCredential)
			return nil
		})
		ctx.vcr.EXPECT().Issue(gomock.Any()).Return(&v, nil)
		err := ctx.client.Create(ctx.echo)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, issuer, vcReturn.Issuer)
	})

	t.Run("error - parse error", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))

		err := ctx.client.Create(ctx.echo)

		assert.EqualError(t, err, "b00m!")
	})

	t.Run("error - issue error", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any())
		ctx.vcr.EXPECT().Issue(gomock.Any()).Return(nil, errors.New("b00m!"))

		err := ctx.client.Create(ctx.echo)

		assert.Error(t, err)
	})

	t.Run("error - issue error", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any())
		ctx.vcr.EXPECT().Issue(gomock.Any()).Return(nil, credential.ErrValidation)

		err := ctx.client.Create(ctx.echo)

		assert.ErrorIs(t, err, credential.ErrValidation)
		assert.Equal(t, http.StatusBadRequest, ctx.client.ResolveStatusCode(err))
	})
}

func TestWrapper_Resolve(t *testing.T) {
	idString := "did:nuts:1#1"
	id, _ := ssi.ParseURI(idString)

	v := vc.VerifiableCredential{
		ID: id,
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		var resolutionResult ResolutionResult
		ctx.vcr.EXPECT().Resolve(*id, nil).Return(&v, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			resolutionResult = f2.(ResolutionResult)
			return nil
		})

		err := ctx.client.Resolve(ctx.echo, idString, ResolveParams{})

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, id, resolutionResult.VerifiableCredential.ID)
		assert.Equal(t, ResolutionResultCurrentStatusTrusted, resolutionResult.CurrentStatus)
	})

	t.Run("ok - with resolveTime", func(t *testing.T) {
		ctx := newMockContext(t)
		timeString := "2020-01-01T12:00:00Z"
		resolveTime, _ := time.Parse(time.RFC3339, timeString)
		ctx.vcr.EXPECT().Resolve(*id, &resolveTime).Return(&v, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		err := ctx.client.Resolve(ctx.echo, idString, ResolveParams{ResolveTime: &timeString})

		if !assert.NoError(t, err) {
			return
		}
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.vcr.EXPECT().Resolve(*id, nil).Return(nil, vcr.ErrNotFound)

		err := ctx.client.Resolve(ctx.echo, idString, ResolveParams{})

		assert.ErrorIs(t, err, vcr.ErrNotFound)
		assert.Equal(t, http.StatusNotFound, ctx.client.ResolveStatusCode(err))
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.vcr.EXPECT().Resolve(*id, nil).Return(nil, errors.New("b00m!"))

		err := ctx.client.Resolve(ctx.echo, idString, ResolveParams{})

		assert.Error(t, err)
	})

	t.Run("error - revoked", func(t *testing.T) {
		ctx := newMockContext(t)

		var resolutionResult ResolutionResult
		ctx.vcr.EXPECT().Resolve(*id, nil).Return(&v, vcr.ErrRevoked)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			resolutionResult = f2.(ResolutionResult)
			return nil
		})

		err := ctx.client.Resolve(ctx.echo, idString, ResolveParams{})

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, id, resolutionResult.VerifiableCredential.ID)
		assert.Equal(t, ResolutionResultCurrentStatusRevoked, resolutionResult.CurrentStatus)
	})

	t.Run("error - untrusted", func(t *testing.T) {
		ctx := newMockContext(t)

		var resolutionResult ResolutionResult
		ctx.vcr.EXPECT().Resolve(*id, nil).Return(&v, vcr.ErrUntrusted)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			resolutionResult = f2.(ResolutionResult)
			return nil
		})

		err := ctx.client.Resolve(ctx.echo, idString, ResolveParams{})

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, id, resolutionResult.VerifiableCredential.ID)
		assert.Equal(t, ResolutionResultCurrentStatusUntrusted, resolutionResult.CurrentStatus)
	})

	t.Run("error - incorrect at param", func(t *testing.T) {
		ctx := newMockContext(t)
		at := "b00m!"

		err := ctx.client.Resolve(ctx.echo, idString, ResolveParams{ResolveTime: &at})

		assert.Error(t, err)
		assert.EqualError(t, err, "failed to parse query parameter 'at': parsing time \"b00m!\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"b00m!\" as \"2006\"")
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
	registry.Add(concept.ExampleConfig)

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
		cpt := concept.Concept(map[string]interface{}{"foo": "bar"})
		ctx.vcr.EXPECT().Search(gomock.Any(), map[string]string{"name": "Because we care B.V."}).Return([]concept.Concept{cpt}, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			capturedConcept = f2.([]concept.Concept)
			return nil
		})

		err := ctx.client.Search(ctx.echo, "human")

		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, capturedConcept, 1)
		assert.Equal(t, cpt, capturedConcept[0])
	})

	t.Run("error - Bind explodes", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).Return(errors.New("b00m!"))

		err := ctx.client.Search(ctx.echo, "unknown")

		assert.EqualError(t, err, "b00m!")
	})

	t.Run("error - search returns error", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.client.CR = registry
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any())
		ctx.vcr.EXPECT().Search(gomock.Any(), map[string]string{}).Return(nil, errors.New("b00m!"))

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

		err := ctx.client.Revoke(ctx.echo, string([]byte{0}))

		assert.Error(t, err)
	})

	t.Run("error - revoke error", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vcr.EXPECT().Revoke(gomock.Any()).Return(nil, vcr.ErrRevoked)

		err := ctx.client.Revoke(ctx.echo, "test")

		assert.ErrorIs(t, err, vcr.ErrRevoked)
		assert.Equal(t, http.StatusConflict, ctx.client.ResolveStatusCode(err))
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
		ctx.echo.EXPECT().NoContent(http.StatusNoContent)

		err := ctx.client.TrustIssuer(ctx.echo)
		assert.NoError(t, err)
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
		ctx.echo.EXPECT().NoContent(http.StatusNoContent)

		err := ctx.client.UntrustIssuer(ctx.echo)
		assert.NoError(t, err)
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

		err := ctx.client.TrustIssuer(ctx.echo)

		assert.EqualError(t, err, "failed to parse issuer: parse \"\\x00\": net/url: invalid control character in URL")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
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

		err := ctx.client.TrustIssuer(ctx.echo)

		assert.EqualError(t, err, "malformed credential type: parse \"\\x00\": net/url: invalid control character in URL")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
	})

	t.Run("error - invalid body", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any()).DoAndReturn(func(f interface{}) error {
			return errors.New("b00m!")
		})

		err := ctx.client.TrustIssuer(ctx.echo)

		assert.EqualError(t, err, "b00m!")
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

func TestWrapper_Trusted(t *testing.T) {
	credentialType, _ := ssi.ParseURI("type")

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		var capturedList []string
		ctx.vcr.EXPECT().Trusted(*credentialType).Return([]ssi.URI{*credentialType}, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f1 interface{}, f2 interface{}) error {
			capturedList = f2.([]string)
			return nil
		})

		err := ctx.client.ListTrusted(ctx.echo, credentialType.String())

		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, capturedList, 1)
		assert.Equal(t, credentialType.String(), capturedList[0])
	})

	t.Run("error", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		err := ctx.client.ListTrusted(ctx.echo, string([]byte{0}))

		assert.Error(t, err)
		assert.ErrorIs(t, err, core.InvalidInputError(""))
	})
}

func TestWrapper_Untrusted(t *testing.T) {
	credentialType, _ := ssi.ParseURI("type")

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		var capturedList []string
		ctx.vcr.EXPECT().Untrusted(*credentialType).Return([]ssi.URI{*credentialType}, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f1 interface{}, f2 interface{}) error {
			capturedList = f2.([]string)
			return nil
		})

		err := ctx.client.ListUntrusted(ctx.echo, credentialType.String())

		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, capturedList, 1)
		assert.Equal(t, credentialType.String(), capturedList[0])
	})

	t.Run("error - malformed input", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		err := ctx.client.ListUntrusted(ctx.echo, string([]byte{0}))

		assert.EqualError(t, err, "malformed credential type: parse \"\\x00\": net/url: invalid control character in URL")
		assert.ErrorIs(t, err, core.InvalidInputError(""))
	})

	t.Run("error - other", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vcr.EXPECT().Untrusted(*credentialType).Return(nil, errors.New("b00m!"))

		err := ctx.client.ListUntrusted(ctx.echo, credentialType.String())

		assert.EqualError(t, err, "b00m!")
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
