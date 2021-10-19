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
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	irma "github.com/privacybydesign/irmago"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	irmaService "github.com/nuts-foundation/nuts-node/auth/services/irma"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/store"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

const orgName = "CareBears"
const orgCity = "Caretown"

var orgConcept = concept.Concept{"organization": concept.Concept{"name": orgName, "city": orgCity}}

var orgID = *vdr.TestDIDA

func TestContract_DrawUpContract(t *testing.T) {
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
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, false, gomock.Any()).AnyTimes().Return(orgConcept, nil)

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
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, false, gomock.Any()).AnyTimes().Return(orgConcept, nil)

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
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, false, gomock.Any()).AnyTimes().Return(orgConcept, nil)

		timeNow = func() time.Time {
			return time.Time{}.Add(10 * time.Second)
		}
		defer func() { timeNow = time.Now }()
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
			assert.Equal(t, "could not draw up contract: no valid organization credential at provided validFrom date", err.Error())
		}
		assert.Nil(t, drawnUpContract)
	})

	t.Run("nok - missing organization name", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, false, gomock.Any()).AnyTimes().Return(concept.Concept{"organization": concept.Concept{"city": orgCity}}, nil)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)

		assert.Nil(t, drawnUpContract)
		assert.EqualError(t, err, "could not draw up contract, could not extract organization name: no value for given path")
	})

	t.Run("nok - missing organization city", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, false, gomock.Any()).AnyTimes().Return(concept.Concept{"organization": concept.Concept{"name": orgName}}, nil)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)

		assert.Nil(t, drawnUpContract)
		assert.EqualError(t, err, "could not draw up contract, could not extract organization city: no value for given path")
	})

	t.Run("nok - unknown private key", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(false)

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
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, false, gomock.Any()).AnyTimes().Return(nil, errors.New("error occurred"))

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
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(true)
		ctx.nameResolver.EXPECT().Get(concept.OrganizationConcept, false, gomock.Any()).AnyTimes().Return(orgConcept, nil)

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
		instance := NewNotary(
			Config{
				ContractValidity: 60 * time.Minute,
			},
			vcr.NewMockResolver(gomock.NewController(t)),
			vcr.NewTestVCRInstance(testDir),
			doc.KeyResolver{Store: store.NewMemoryStore()},
			crypto.NewTestCryptoInstance(testDir),
		)

		if !assert.NotNil(t, instance) {
			return
		}

		n, ok := instance.(*notary)
		if !assert.True(t, ok) {
			return
		}

		assert.NotNil(t, n.privateKeyStore)
		assert.NotNil(t, n.conceptFinder)
		assert.NotNil(t, n.keyResolver)
		assert.NotNil(t, n.config.ContractValidity)
	})
}

const qrURL = "https://api.nuts-test.example" + irmaService.IrmaMountPath + "/123-session-ref-123"

func TestService_CreateContractSession(t *testing.T) {
	t.Run("Create a new session", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		request := services.CreateSessionRequest{
			Message:      "message to sign",
			SigningMeans: irmaService.ContractFormat,
		}
		ctx.signerMock.EXPECT().StartSigningSession(gomock.Any()).Return(irmaService.SessionPtr{ID: "abc-sessionid-abc", QrCodeInfo: irma.Qr{URL: qrURL, Type: irma.ActionSigning}}, nil)

		result, err := ctx.notary.CreateSigningSession(request)

		if !assert.NoError(t, err) {
			return
		}

		irmaResult := result.(irmaService.SessionPtr)

		assert.Equal(t, irmaResult.QrCodeInfo.URL, qrURL, "qrCode should contain the correct URL")
		assert.Equal(t, irmaResult.QrCodeInfo.Type, irma.ActionSigning, "qrCode type should be signing")
	})
}

func TestContract_Configure(t *testing.T) {
	t.Run("ok - config valid", func(t *testing.T) {
		c := notary{
			config: Config{
				PublicURL:             "url",
				IrmaConfigPath:        "../../../development/irma",
				IrmaSchemeManager:     "empty",
				AutoUpdateIrmaSchemas: false,
				ContractValidators:    []string{"irma", "dummy"},
			},
		}

		assert.NoError(t, c.Configure())
	})
}

func TestContract_VerifyVP(t *testing.T) {
	t.Run("ok - valid VP", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		rawVP, err := json.Marshal(struct {
			Type []string
		}{Type: []string{"bar"}})
		if !assert.NoError(t, err) {
			return
		}

		mockVerifier := services.NewMockContractNotary(ctrl)
		mockVerifier.EXPECT().VerifyVP(rawVP, nil).Return(services.TestVPVerificationResult{Val: contract.Valid}, nil)

		validator := notary{verifiers: map[contract.VPType]contract.VPVerifier{"bar": mockVerifier}}

		validationResult, err := validator.VerifyVP(rawVP, nil)

		if !assert.NoError(t, err) {
			return
		}
		if !assert.NotNil(t, validationResult) {
			return
		}
		assert.Equal(t, contract.Valid, validationResult.Validity())
	})

	t.Run("nok - unknown VerifiablePresentation", func(t *testing.T) {
		validator := notary{}

		rawVP, err := json.Marshal(struct {
			Type []string
		}{Type: []string{"bar"}})
		if !assert.NoError(t, err) {
			return
		}

		validationResult, err := validator.VerifyVP(rawVP, nil)
		if !assert.Error(t, err) {
			return
		}
		if !assert.Nil(t, validationResult) {
			return
		}
		assert.Equal(t, "unknown VerifiablePresentation type: bar", err.Error())
	})

	t.Run("nok - missing custom type", func(t *testing.T) {
		validator := notary{}

		rawVP, err := json.Marshal(struct {
			foo string
		}{foo: "bar"})
		if !assert.NoError(t, err) {
			return
		}

		validationResult, err := validator.VerifyVP(rawVP, nil)
		if !assert.Error(t, err) {
			return
		}
		if !assert.Nil(t, validationResult) {
			return
		}
		assert.Equal(t, "unprocessable VerifiablePresentation, exactly 1 custom type is expected", err.Error())
	})

	t.Run("nok - invalid rawVP", func(t *testing.T) {
		validator := notary{}
		validationResult, err := validator.VerifyVP([]byte{}, nil)
		if !assert.Error(t, err) {
			return
		}
		if !assert.Nil(t, validationResult) {
			return
		}
		assert.Equal(t, "unable to verifyVP: unexpected end of JSON input", err.Error())
	})
}

func TestContract_SigningSessionStatus(t *testing.T) {
	t.Run("ok - valid session", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		sessionID := "123"

		mockSigner := contract.NewMockSigner(ctrl)
		mockSigner.EXPECT().SigningSessionStatus(sessionID).Return(&contract.MockSigningSessionResult{}, nil)

		validator := notary{signers: map[contract.SigningMeans]contract.Signer{"bar": mockSigner}}

		signingSessionResult, err := validator.SigningSessionStatus(sessionID)
		if !assert.NoError(t, err) {
			return
		}
		if !assert.NotNil(t, signingSessionResult) {
			return
		}
	})

	t.Run("nok - session not found", func(t *testing.T) {
		validator := notary{}
		sessionID := "123"
		signingSesionResult, err := validator.SigningSessionStatus(sessionID)

		if !assert.Error(t, err) {
			return
		}
		if !assert.Nil(t, signingSesionResult) {
			return
		}
		assert.Equal(t, "session not found", err.Error())
	})
}

type testContext struct {
	ctrl *gomock.Controller

	signerMock   *contract.MockSigner
	nameResolver *vcr.MockConceptFinder
	keyResolver  *types.MockKeyResolver
	keyStore     *crypto.MockKeyStore
	notary       notary
}

func buildContext(t *testing.T) *testContext {
	ctrl := gomock.NewController(t)

	signerMock := contract.NewMockSigner(ctrl)

	signers := map[contract.SigningMeans]contract.Signer{}
	signers["irma"] = signerMock

	ctx := &testContext{
		ctrl:         ctrl,
		nameResolver: vcr.NewMockConceptFinder(ctrl),
		keyResolver:  types.NewMockKeyResolver(ctrl),
		keyStore:     crypto.NewMockKeyStore(ctrl),
		signerMock:   signerMock,
	}

	notary := notary{
		keyResolver:     ctx.keyResolver,
		privateKeyStore: ctx.keyStore,
		conceptFinder:   ctx.nameResolver,
		signers:         signers,
		config: Config{
			ContractValidity: 15 * time.Minute,
		},
	}

	ctx.notary = notary

	return ctx
}
