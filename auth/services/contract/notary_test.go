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
	"context"
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/jsonld"
	irma "github.com/privacybydesign/irmago"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	irmaService "github.com/nuts-foundation/nuts-node/auth/services/irma"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/store"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

var orgID = *vdr.TestDIDA

func TestContract_DrawUpContract(t *testing.T) {
	template := contract.Template{
		Template: "Organisation Name: {{legal_entity}} in {{legal_entity_city}}, valid from {{valid_from}} to {{valid_to}}",
	}
	validFrom := time.Unix(0, 0)
	duration := 10 * time.Minute

	// Create DID document for org
	keyID := orgID
	keyID.Fragment = "key-1"

	searchTerms := []vcr.SearchTerm{
		{IRIPath: jsonld.CredentialSubjectPath, Value: orgID.String()},
		{IRIPath: jsonld.OrganizationNamePath, Type: vcr.NotNil},
		{IRIPath: jsonld.OrganizationCityPath, Type: vcr.NotNil},
	}

	testCredential := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestOrganizationCredential), &testCredential)

	t.Run("draw up valid contract", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(true)
		ctx.vcr.EXPECT().Search(context.Background(), searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)
		require.NoError(t, err)

		assert.NotNil(t, drawnUpContract)
		assert.Equal(t, "Organisation Name: CareBears in Caretown, valid from Thursday, 1 January 1970 01:00:00 to Thursday, 1 January 1970 01:10:00", drawnUpContract.RawContractText)
	})

	t.Run("no given duration uses default", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(true)
		ctx.vcr.EXPECT().Search(context.Background(), searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, 0)
		require.NoError(t, err)

		assert.NotNil(t, drawnUpContract)
		assert.Equal(t, "Organisation Name: CareBears in Caretown, valid from Thursday, 1 January 1970 01:00:00 to Thursday, 1 January 1970 01:15:00", drawnUpContract.RawContractText)
	})

	t.Run("no given time uses time.Now()", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(true)
		ctx.vcr.EXPECT().Search(context.Background(), searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)

		timeNow = func() time.Time {
			return time.Unix(0, 0).Add(10 * time.Second)
		}
		defer func() { timeNow = time.Now }()
		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, time.Time{}, 0)
		require.NoError(t, err)

		assert.NotNil(t, drawnUpContract)
		assert.Equal(t, "Organisation Name: CareBears in Caretown, valid from Thursday, 1 January 1970 01:00:10 to Thursday, 1 January 1970 01:15:10", drawnUpContract.RawContractText)
	})

	t.Run("nok - unknown organization", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return("", types.ErrNotFound)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)

		assert.EqualError(t, err, "could not draw up contract: no valid organization credential at provided validFrom date")
		assert.Nil(t, drawnUpContract)
	})

	t.Run("nok - unknown private key", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(false)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)

		assert.EqualError(t, err, "could not draw up contract: organization is not managed by this node: missing organization private key")
		assert.Nil(t, drawnUpContract)
	})

	t.Run("nok - other DID resolver error", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return("", errors.New("error occurred"))

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)

		assert.EqualError(t, err, "could not draw up contract: error occurred")
		assert.Nil(t, drawnUpContract)
	})

	t.Run("nok - could not find credential", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(true)
		ctx.vcr.EXPECT().Search(context.Background(), searchTerms, false, nil).Return(nil, errors.New("error occurred"))

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)

		assert.EqualError(t, err, "could not find a credential: error occurred")
		assert.Nil(t, drawnUpContract)
	})

	t.Run("nok - render error", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(true)
		ctx.vcr.EXPECT().Search(context.Background(), searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential}, nil)

		template := contract.Template{
			Template: "Organisation Name: {{{legal_entity}}, valid from {{valid_from}} to {{valid_to}}",
		}

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)

		assert.EqualError(t, err, "could not draw up contract: could not render contract template: line 1: unmatched open tag")
		assert.Nil(t, drawnUpContract)
	})

	t.Run("ok - multiple (matching) VCs", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(true)
		ctx.vcr.EXPECT().Search(context.Background(), searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential, testCredential}, nil)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)

		require.NoError(t, err)
		assert.NotNil(t, drawnUpContract)
		assert.Equal(t, "Organisation Name: CareBears in Caretown, valid from Thursday, 1 January 1970 01:00:00 to Thursday, 1 January 1970 01:10:00", drawnUpContract.RawContractText)
	})

	t.Run("nok - multiple non-matching VCs", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		testCredential2 := vc.VerifiableCredential{}
		_ = json.Unmarshal([]byte(jsonld.TestCredential), &testCredential2)

		ctx.keyResolver.EXPECT().ResolveSigningKeyID(orgID, gomock.Any()).Return(keyID.String(), nil)
		ctx.keyStore.EXPECT().Exists(keyID.String()).Return(true)
		ctx.vcr.EXPECT().Search(context.Background(), searchTerms, false, nil).Return([]vc.VerifiableCredential{testCredential, testCredential2}, nil)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)

		assert.EqualError(t, err, "found multiple non-matching VCs, which is not supported")
		assert.Nil(t, drawnUpContract)
	})
}

func TestNewContractNotary(t *testing.T) {
	t.Run("adds all services", func(t *testing.T) {
		instance := NewNotary(
			Config{
				ContractValidity: 60 * time.Minute,
			},
			vcr.NewTestVCRInstance(t),
			didservice.KeyResolver{Store: store.NewTestStore(t)},
			crypto.NewTestCryptoInstance(),
			nil,
		)

		require.NotNil(t, instance)

		n, ok := instance.(*notary)
		require.True(t, ok)

		assert.NotNil(t, n.vcr)
		assert.NotNil(t, n.keyResolver)
		assert.NotNil(t, n.privateKeyStore)
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

		require.NoError(t, err)

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
	rawVP := vc.VerifiablePresentation{
		Type: []ssi.URI{vc.VerifiablePresentationTypeV1URI(), ssi.MustParseURI("bar")},
	}
	t.Run("ok - valid VP", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockVerifier := services.NewMockContractNotary(ctrl)
		mockVerifier.EXPECT().VerifyVP(rawVP, nil).Return(services.TestVPVerificationResult{Val: contract.Valid}, nil)
		validator := notary{verifiers: map[string]contract.VPVerifier{"bar": mockVerifier}}

		validationResult, err := validator.VerifyVP(rawVP, nil)

		require.NoError(t, err)
		require.NotNil(t, validationResult)
		assert.Equal(t, contract.Valid, validationResult.Validity())
	})

	t.Run("nok - unknown VerifiablePresentation", func(t *testing.T) {
		validator := notary{}

		validationResult, err := validator.VerifyVP(rawVP, nil)

		assert.Nil(t, validationResult)
		assert.EqualError(t, err, "unknown VerifiablePresentation type: bar")
	})

	t.Run("nok - missing custom type", func(t *testing.T) {
		validator := notary{}
		rawVP := vc.VerifiablePresentation{
			Type: []ssi.URI{vc.VerifiablePresentationTypeV1URI()},
		}

		validationResult, err := validator.VerifyVP(rawVP, nil)

		assert.Nil(t, validationResult)
		assert.EqualError(t, err, "unprocessable VerifiablePresentation, exactly 1 custom type is expected")
	})
}

func TestContract_SigningSessionStatus(t *testing.T) {
	t.Run("ok - valid session", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		sessionID := "123"

		mockSigner := contract.NewMockSigner(ctrl)
		mockSigner.EXPECT().SigningSessionStatus(sessionID).Return(&contract.MockSigningSessionResult{}, nil)

		validator := notary{signers: map[string]contract.Signer{"bar": mockSigner}}

		signingSessionResult, err := validator.SigningSessionStatus(sessionID)
		require.NoError(t, err)
		require.NotNil(t, signingSessionResult)
	})

	t.Run("nok - session not found", func(t *testing.T) {
		validator := notary{}
		sessionID := "123"
		signingSesionResult, err := validator.SigningSessionStatus(sessionID)

		assert.Nil(t, signingSesionResult)
		assert.EqualError(t, err, "session not found")
	})
}

type testContext struct {
	ctrl *gomock.Controller

	signerMock  *contract.MockSigner
	vcr         *vcr.MockFinder
	keyResolver *types.MockKeyResolver
	keyStore    *crypto.MockKeyStore
	notary      notary
}

func buildContext(t *testing.T) *testContext {
	ctrl := gomock.NewController(t)

	signerMock := contract.NewMockSigner(ctrl)

	signers := map[string]contract.Signer{}
	signers["irma"] = signerMock

	ctx := &testContext{
		ctrl:        ctrl,
		vcr:         vcr.NewMockFinder(ctrl),
		keyResolver: types.NewMockKeyResolver(ctrl),
		keyStore:    crypto.NewMockKeyStore(ctrl),
		signerMock:  signerMock,
	}

	notary := notary{
		keyResolver:     ctx.keyResolver,
		privateKeyStore: ctx.keyStore,
		vcr:             ctx.vcr,
		signers:         signers,
		config: Config{
			ContractValidity: 15 * time.Minute,
		},
		jsonldManager: jsonld.NewTestJSONLDManager(t),
	}

	ctx.notary = notary

	return ctx
}
