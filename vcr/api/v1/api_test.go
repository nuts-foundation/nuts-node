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
	"github.com/nuts-foundation/nuts-node/test"

	"net/http"
	"testing"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vdr"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/stretchr/testify/assert"
)

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

		test.AssertIsError(t, err, credential.ErrValidation)
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
		defer ctx.ctrl.Finish()

		var resolutionResult ResolutionResult
		ctx.vcr.EXPECT().Resolve(*id).Return(&v, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			resolutionResult = f2.(ResolutionResult)
			return nil
		})

		err := ctx.client.Resolve(ctx.echo, idString)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, id, resolutionResult.VerifiableCredential.ID)
		assert.Equal(t, ResolutionResultCurrentStatusTrusted, resolutionResult.CurrentStatus)
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vcr.EXPECT().Resolve(*id).Return(nil, vcr.ErrNotFound)

		err := ctx.client.Resolve(ctx.echo, idString)

		test.AssertIsError(t, err, vcr.ErrNotFound)
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
		ctx.vcr.EXPECT().Resolve(*id).Return(&v, vcr.ErrRevoked)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			resolutionResult = f2.(ResolutionResult)
			return nil
		})

		err := ctx.client.Resolve(ctx.echo, idString)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, id, resolutionResult.VerifiableCredential.ID)
		assert.Equal(t, ResolutionResultCurrentStatusRevoked, resolutionResult.CurrentStatus)
	})

	t.Run("error - revoked", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		var resolutionResult ResolutionResult
		ctx.vcr.EXPECT().Resolve(*id).Return(&v, vcr.ErrUntrusted)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			resolutionResult = f2.(ResolutionResult)
			return nil
		})

		err := ctx.client.Resolve(ctx.echo, idString)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, id, resolutionResult.VerifiableCredential.ID)
		assert.Equal(t, ResolutionResultCurrentStatusUntrusted, resolutionResult.CurrentStatus)
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
		ctx.vcr.EXPECT().Search(gomock.Any()).Return([]vc.VerifiableCredential{concept.TestVC()}, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any()).DoAndReturn(func(f interface{}, f2 interface{}) error {
			capturedConcept = f2.([]concept.Concept)
			return nil
		})

		err := ctx.client.Search(ctx.echo, "human")

		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, capturedConcept, 1)
		assert.Equal(t, "did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY#123", capturedConcept[0]["id"])
		assert.Equal(t, "HumanCredential", capturedConcept[0]["type"])
	})

	t.Run("error - unknown template", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.client.CR = registry
		defer ctx.ctrl.Finish()

		ctx.echo.EXPECT().Bind(gomock.Any())

		err := ctx.client.Search(ctx.echo, "unknown")

		test.AssertIsError(t, err, concept.ErrUnknownConcept)
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

		err := ctx.client.Revoke(ctx.echo, string([]byte{0}))

		assert.Error(t, err)
	})

	t.Run("error - revoke error", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.vcr.EXPECT().Revoke(gomock.Any()).Return(nil, vcr.ErrRevoked)

		err := ctx.client.Revoke(ctx.echo, "test")

		test.AssertIsError(t, err, vcr.ErrRevoked)
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
		ctx.echo.EXPECT().NoContent(http.StatusNoContent)

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

		err := ctx.client.TrustIssuer(ctx.echo)

		assert.EqualError(t, err, "failed to parse issuer: parse \"\\x00\": net/url: invalid control character in URL")
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

		assert.EqualError(t, err, "failed to parse credential type: parse \"\\x00\": net/url: invalid control character in URL")
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
