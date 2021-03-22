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
 */

package contract

import (
	"errors"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/auth/contract"
)

const orgName = "CareBears"

var orgConceptName = concept.Concept{"organization": concept.Concept{"name": orgName}}

var orgID = *vdr.TestDIDA

func Test_contractNotaryService_ValidateContract(t *testing.T) {
	// TODO: Re-enable this test (https://github.com/nuts-foundation/nuts-node/issues/91)
	t.SkipNow()
	t.Run("it could validate a valid contract", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		nameResolver := vcr.NewMockConceptFinder(ctrl)

		nameResolver.EXPECT().Get(concept.OrganizationConcept, orgID).Return(orgName, "", nil)

		cns := contractNotaryService{conceptFinder: nameResolver}

		contractTemplate, err := contract.StandardContractTemplates.FindFromRawContractText("EN:PractitionerLogin:v3")
		if !assert.NoError(t, err) {
			return
		}

		contractToCheck, err := contractTemplate.Render(map[string]string{
			contract.LegalEntityAttr: orgName,
		}, time.Now().Add(-10*time.Minute), 20*time.Minute)
		if !assert.NoError(t, err) {
			return
		}

		ok, err := cns.ValidateContract(*contractToCheck, orgID, time.Now())
		assert.True(t, ok)
		assert.NoError(t, err)
	})
}

func Test_contractNotaryService_DrawUpContract(t *testing.T) {
	type testContext struct {
		ctrl            *gomock.Controller
		nameResolver    *vcr.MockConceptFinder
		didResolver     *types.MockResolver
		privateKeyStore *crypto.MockPrivateKeyStore
		notary          contractNotaryService
	}
	buildContext := func(t *testing.T) *testContext {
		ctrl := gomock.NewController(t)
		ctx := &testContext{
			ctrl:            ctrl,
			nameResolver:    vcr.NewMockConceptFinder(ctrl),
			didResolver:     types.NewMockResolver(ctrl),
			privateKeyStore: crypto.NewMockPrivateKeyStore(ctrl),
		}
		notary := contractNotaryService{
			didResolver:      ctx.didResolver,
			privateKeyStore:  ctx.privateKeyStore,
			conceptFinder:    ctx.nameResolver,
			contractValidity: 15 * time.Minute,
		}
		ctx.notary = notary
		return ctx
	}

	template := contract.Template{
		Template: "Organisation Name: {{legal_entity}}, valid from {{valid_from}} to {{valid_to}}",
	}
	// Add 1 second so !time.Zero()
	validFrom := time.Time{}.Add(time.Second)
	duration := 10 * time.Minute

	// Create DID document for org
	keyID := orgID
	keyID.Fragment = "key-1"

	t.Run("draw up valid contract", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.didResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, gomock.Any()).AnyTimes().Return(orgConceptName, nil)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)
		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, drawnUpContract)
		assert.Equal(t, "Organisation Name: CareBears, valid from maandag, 1 januari 0001 00:19:33 to maandag, 1 januari 0001 00:29:33", drawnUpContract.RawContractText)
	})

	t.Run("no given duration uses default", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.didResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, gomock.Any()).AnyTimes().Return(orgConceptName, nil)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, 0)
		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, drawnUpContract)
		assert.Equal(t, "Organisation Name: CareBears, valid from maandag, 1 januari 0001 00:19:33 to maandag, 1 januari 0001 00:34:33", drawnUpContract.RawContractText)
	})

	t.Run("no given time uses time.Now()", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.didResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, gomock.Any()).AnyTimes().Return(orgConceptName, nil)

		timenow = func() time.Time {
			return time.Time{}.Add(10 * time.Second)
		}
		defer func() { timenow = time.Now }()
		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, time.Time{}, 0)
		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, drawnUpContract)
		assert.Equal(t, "Organisation Name: CareBears, valid from maandag, 1 januari 0001 00:19:42 to maandag, 1 januari 0001 00:34:42", drawnUpContract.RawContractText)
	})

	t.Run("nok - unknown organization", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.didResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return("", types.ErrNotFound)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)
		if assert.Error(t, err) {
			assert.Equal(t, "could not draw up contract: organization not found", err.Error())
		}
		assert.Nil(t, drawnUpContract)
	})

	t.Run("nok - unknown private key", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.didResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(keyID.String()).Return(false)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)
		if assert.Error(t, err) {
			assert.Equal(t, "could not draw up contract: organization is not managed by this node: missing organization private key", err.Error())
		}
		assert.Nil(t, drawnUpContract)
	})

	t.Run("nok - other DID resolver error", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.didResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return("", errors.New("error occurred"))

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)
		if assert.Error(t, err) {
			assert.Equal(t, "could not draw up contract: error occurred", err.Error())
		}
		assert.Nil(t, drawnUpContract)
	})

	t.Run("nok - other name resolver error", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.didResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, gomock.Any()).AnyTimes().Return(nil, errors.New("error occurred"))

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)
		if assert.Error(t, err) {
			assert.Equal(t, "could not draw up contract: error occurred", err.Error())
		}
		assert.Nil(t, drawnUpContract)
	})

	t.Run("nok - render error", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.didResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, gomock.Any()).AnyTimes().Return(orgConceptName, nil)

		template := contract.Template{
			Template: "Organisation Name: {{{legal_entity}}, valid from {{valid_from}} to {{valid_to}}",
		}

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)
		if assert.Error(t, err) {
			assert.Equal(t, "could not draw up contract: could not render contract template: line 1: unmatched open tag", err.Error())
		}
		assert.Nil(t, drawnUpContract)
	})
}

func TestNewContractNotary(t *testing.T) {
	t.Run("adds all services", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		instance := NewContractNotary(
			vdr.NewDummyNameResolver(),
			vdr.NewTestVDRInstance(testDir),
			crypto.NewTestCryptoInstance(testDir),
			60 * time.Minute,
		)

		if !assert.NotNil(t, instance) {
			return
		}

		service, ok := instance.(*contractNotaryService)
		if !assert.True(t, ok) {
			return
		}

		assert.NotNil(t, service.privateKeyStore)
		assert.NotNil(t, service.nameResolver)
		assert.NotNil(t, service.didResolver)
		assert.NotNil(t, service.contractValidity)
	})
}