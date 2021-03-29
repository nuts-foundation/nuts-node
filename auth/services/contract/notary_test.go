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
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/auth/contract"
)

const orgName = "CareBears"
const orgCity = "Caretown"

var orgConcept = concept.Concept{"organization": concept.Concept{"name": orgName, "city": orgCity}}

var orgID = *vdr.TestDIDA

func Test_contractNotaryService_DrawUpContract(t *testing.T) {
<<<<<<< HEAD
	type testContext struct {
		ctrl            *gomock.Controller
		nameResolver    *vcr.MockConceptFinder
		keyResolver     *types.MockKeyResolver
		privateKeyStore *crypto.MockPrivateKeyStore
		notary          contractNotaryService
	}
	buildContext := func(t *testing.T) *testContext {
		ctrl := gomock.NewController(t)
		ctx := &testContext{
			ctrl:            ctrl,
			nameResolver:    vcr.NewMockConceptFinder(ctrl),
			keyResolver:     types.NewMockKeyResolver(ctrl),
			privateKeyStore: crypto.NewMockPrivateKeyStore(ctrl),
		}
		notary := contractNotaryService{
			conceptFinder:    ctx.nameResolver,
			keyResolver:      ctx.keyResolver,
			privateKeyStore:  ctx.privateKeyStore,
			contractValidity: 15 * time.Minute,
		}
		ctx.notary = notary
		return ctx
	}
=======
>>>>>>> Removed validation from notary

	template := contract.Template{
		Template: "Organisation Name: {{legal_entity}} in {{legal_entity_city}}, valid from {{valid_from}} to {{valid_to}}",
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

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, gomock.Any()).AnyTimes().Return(orgConcept, nil)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)
		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, drawnUpContract)
		assert.Equal(t, "Organisation Name: CareBears in Caretown, valid from Monday, 1 January 0001 00:19:33 to Monday, 1 January 0001 00:29:33", drawnUpContract.RawContractText)
	})

	t.Run("no given duration uses default", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, gomock.Any()).AnyTimes().Return(orgConcept, nil)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, 0)
		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, drawnUpContract)
		assert.Equal(t, "Organisation Name: CareBears in Caretown, valid from Monday, 1 January 0001 00:19:33 to Monday, 1 January 0001 00:34:33", drawnUpContract.RawContractText)
	})

	t.Run("no given time uses time.Now()", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, gomock.Any()).AnyTimes().Return(orgConcept, nil)

		timenow = func() time.Time {
			return time.Time{}.Add(10 * time.Second)
		}
		defer func() { timenow = time.Now }()
		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, time.Time{}, 0)
		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, drawnUpContract)
		assert.Equal(t, "Organisation Name: CareBears in Caretown, valid from Monday, 1 January 0001 00:19:42 to Monday, 1 January 0001 00:34:42", drawnUpContract.RawContractText)
	})

	t.Run("nok - unknown organization", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return("", types.ErrNotFound)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)
		if assert.Error(t, err) {
			assert.Equal(t, "could not draw up contract: organization not found", err.Error())
		}
		assert.Nil(t, drawnUpContract)
	})

	t.Run("nok - missing organization name", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, gomock.Any()).AnyTimes().Return(concept.Concept{"organization": concept.Concept{"city": orgCity}}, nil)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)

		assert.Nil(t, drawnUpContract)
		assert.EqualError(t, err, "could not draw up contract, could not extract organization name: no value for given path")
	})

	t.Run("nok - missing organization city", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, gomock.Any()).AnyTimes().Return(concept.Concept{"organization": concept.Concept{"name": orgName}}, nil)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)

		assert.Nil(t, drawnUpContract)
		assert.EqualError(t, err, "could not draw up contract, could not extract organization city: no value for given path")
	})

	t.Run("nok - unknown private key", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
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

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return("", errors.New("error occurred"))

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)
		if assert.Error(t, err) {
			assert.Equal(t, "could not draw up contract: error occurred", err.Error())
		}
		assert.Nil(t, drawnUpContract)
	})

	t.Run("nok - other name resolver error", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
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

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.privateKeyStore.EXPECT().PrivateKeyExists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, gomock.Any()).AnyTimes().Return(orgConcept, nil)

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
		vdrInstance := vdr.NewTestVDRInstance(testDir)
		instance := NewContractNotary(
			vcr.NewTestVCRInstance(testDir),
			vdr.KeyResolver{DocResolver: vdrInstance},
			crypto.NewTestCryptoInstance(testDir),
			60*time.Minute,
		)

		if !assert.NotNil(t, instance) {
			return
		}

		service, ok := instance.(*contractNotaryService)
		if !assert.True(t, ok) {
			return
		}

		assert.NotNil(t, service.privateKeyStore)
		assert.NotNil(t, service.conceptFinder)
		assert.NotNil(t, service.keyResolver)
		assert.NotNil(t, service.contractValidity)
	})
}

type testContext struct {
	ctrl            *gomock.Controller
	nameResolver    *vcr.MockConceptFinder
	vcResolver      *vcr.MockResolver
	didResolver     *types.MockResolver
	conceptRegistry *concept.MockReader
	privateKeyStore *crypto.MockPrivateKeyStore
	notary          contractNotaryService
}

func buildContext(t *testing.T) *testContext {
	ctrl := gomock.NewController(t)
	vcResolver := vcr.NewMockResolver(ctrl)
	conceptRegistry := concept.NewMockReader(ctrl)
	vcResolver.EXPECT().Registry().Return(conceptRegistry).AnyTimes()
	ctx := &testContext{
		ctrl:            ctrl,
		nameResolver:    vcr.NewMockConceptFinder(ctrl),
		vcResolver:      vcResolver,
		didResolver:     types.NewMockResolver(ctrl),
		privateKeyStore: crypto.NewMockPrivateKeyStore(ctrl),
		conceptRegistry: conceptRegistry,
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
