/*
* Nuts auth
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

package irma

import (
	"encoding/base64"
	"testing"

	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/test"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/test/io"
	irma "github.com/privacybydesign/irmago"
	irmaservercore "github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/assert"

	"encoding/json"
)

type mockIrmaClient struct {
	err           error
	sessionResult *irmaservercore.SessionResult
	irmaQr        *irma.Qr
	sessionToken  string
}

func (m *mockIrmaClient) GetSessionResult(token string) *irmaservercore.SessionResult {
	if m.err != nil {
		return nil
	}
	return m.sessionResult
}

func (m *mockIrmaClient) StartSession(request interface{}, handler irmaservercore.SessionHandler) (*irma.Qr, irma.RequestorToken, *irma.FrontendSessionRequest, error) {
	if m.err != nil {
		return nil, "", nil, m.err
	}

	return m.irmaQr, irma.RequestorToken(m.sessionToken), nil, nil
}

//
//func TestDefaultValidator_legalEntityFromContract(t *testing.T) {
//	type TestContext struct {
//		ctrl  *gomock.Controller
//		v     Service
//		rMock *registryMock.MockRegistryClient
//	}
//	createContext := func(t *testing.T) TestContext {
//		ctrl := gomock.NewController(t)
//		rMock := registryMock.NewMockRegistryClient(ctrl)
//
//		v := Service{
//			Registry: rMock,
//		}
//
//		return TestContext{ctrl: ctrl, v: v, rMock: rMock}
//	}
//
//	t.Run("Empty message returns error", func(t *testing.T) {
//		ctx := createContext(t)
//		defer ctx.ctrl.Finish()
//		_, err := ctx.v.legalEntityFromContract(&SignedIrmaContract{IrmaContract: irma.SignedMessage{}, contract: &contract.Contract{}})
//
//		assert.NotNil(t, err)
//		assert.Error(t, contract.ErrInvalidContractText, err)
//	})
//
//	t.Run("Missing legalEntity returns error", func(t *testing.T) {
//		ctx := createContext(t)
//		defer ctx.ctrl.Finish()
//		rawText := "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens  en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42."
//		signedContract, err := contract.ParseContractString(rawText, contract.StandardContractTemplates)
//
//		assert.Nil(t, signedContract)
//		assert.NotNil(t, err)
//		assert.True(t, errors.Is(err, contract.ErrInvalidContractText))
//	})
//
//	t.Run("Unknown legalEntity returns error", func(t *testing.T) {
//		ctx := createContext(t)
//		defer ctx.ctrl.Finish()
//
//		ctx.rMock.EXPECT().ReverseLookup("UNKNOWN").Return(nil, db.ErrOrganizationNotFound)
//
//		rawText := "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens UNKNOWN en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42."
//		signedContract, err := contract.ParseContractString(rawText, contract.StandardContractTemplates)
//
//		assert.Nil(t, err)
//
//		_, err = ctx.v.legalEntityFromContract(&SignedIrmaContract{
//			contract: signedContract,
//		})
//
//		assert.NotNil(t, err)
//		assert.True(t, errors.Is(err, db.ErrOrganizationNotFound))
//	})
//}

func TestService_VerifyVP(t *testing.T) {
	t.Run("ok - valid VP", func(t *testing.T) {
		validator, _ := defaultValidator(t)

		irmaSignature := test.ValidIrmaContract
		encodedIrmaSignature := base64.StdEncoding.EncodeToString([]byte(irmaSignature))

		vp := VerifiablePresentation{
			Proof: VPProof{
				Proof:      contract.Proof{Type: ""},
				ProofValue: encodedIrmaSignature,
			},
		}

		rawIrmaVP, err := json.Marshal(vp)
		if !assert.NoError(t, err) {
			return
		}
		validationResult, err := validator.VerifyVP(rawIrmaVP, nil)

		if !assert.NoError(t, err) {
			return
		}

		if !assert.NotNil(t, validationResult) {
			return
		}
	})

	t.Run("nok - invalid rawVP", func(t *testing.T) {
		validator := Service{}
		validationResult, err := validator.VerifyVP([]byte{}, nil)

		assert.Nil(t, validationResult)
		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, "could not verify VP: unexpected end of JSON input", err.Error())

	})
}

func TestIrmaVPVerificationResult(t *testing.T) {
	vr := irmaVPVerificationResult{
		validity:            contract.Valid,
		vpType:              contract.VPType("type"),
		disclosedAttributes: map[string]string{
			"gemeente.personalData.familyname": "tester",
			"gemeente.personalData.initials": "i",
			"gemeente.personalData.prefix": "von",
			"sidn-pbdf.email.email": "info@example.com",
		},
		contractAttributes:  map[string]string{
			"a": "b",
		},
	}

	t.Run("attribute mapping", func(t *testing.T) {
		assert.Equal(t, "i", vr.DisclosedAttribute(services.InitialsTokenClaim))
		assert.Equal(t, "tester", vr.DisclosedAttribute(services.FamilyNameTokenClaim))
		assert.Equal(t, "von", vr.DisclosedAttribute(services.PrefixTokenClaim))
		assert.Equal(t, "info@example.com", vr.DisclosedAttribute(services.EmailTokenClaim))
	})

	t.Run("validity", func(t *testing.T) {
		assert.Equal(t, contract.Valid, vr.Validity())
	})

	t.Run("type", func(t *testing.T) {
		assert.Equal(t, contract.VPType("type"), vr.VPType())
	})

	t.Run("DisclosedAttributes", func(t *testing.T) {
		assert.NotNil(t, vr.DisclosedAttributes())
	})

	t.Run("ContractAttributes", func(t *testing.T) {
		assert.NotNil(t, vr.ContractAttributes())
		assert.Equal(t, "b", vr.ContractAttribute("a"))
	})
}

func defaultValidator(t *testing.T) (Service, crypto.KeyStore) {
	t.Helper()
	address := "localhost:1323"
	serviceConfig := ValidatorConfig{
		IrmaSchemeManager:     "empty",
		AutoUpdateIrmaSchemas: true,
		IrmaConfigPath:        "../../../development/irma",
		PublicURL:             "http://" + address,
	}

	irmaConfig, err := GetIrmaConfig(serviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	return Service{
		IrmaConfig:        irmaConfig,
		ContractTemplates: contract.StandardContractTemplates,
	}, crypto.NewTestCryptoInstance(io.TestDirectory(t))
}
