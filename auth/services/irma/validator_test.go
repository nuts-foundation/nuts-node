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
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/test"
	"github.com/nuts-foundation/nuts-node/crypto"
	irma "github.com/privacybydesign/irmago"
	irmaservercore "github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/assert"
)

type mockIrmaClient struct {
	err           error
	sessionResult *irmaservercore.SessionResult
	irmaQr        *irma.Qr
	sessionToken  string
}

func (m *mockIrmaClient) GetSessionResult(token string) (*irmaservercore.SessionResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.sessionResult, nil
}

func (m *mockIrmaClient) StartSession(request interface{}, handler irmaservercore.SessionHandler) (*irma.Qr, irma.RequestorToken, *irma.FrontendSessionRequest, error) {
	if m.err != nil {
		return nil, "", nil, m.err
	}

	return m.irmaQr, irma.RequestorToken(m.sessionToken), nil, nil
}

func (m *mockIrmaClient) HandlerFunc() http.HandlerFunc {
	//TODO implement me
	panic("implement me")
}

func TestService_VerifyVP(t *testing.T) {
	t.Run("ok - valid VP", func(t *testing.T) {
		validator, _ := defaultValidator(t)

		irmaSignature := test.ValidIrmaContract
		encodedIrmaSignature := base64.StdEncoding.EncodeToString([]byte(irmaSignature))

		vp := vc.VerifiablePresentation{
			Proof: []interface{}{VPProof{
				Type:       "type",
				ProofValue: encodedIrmaSignature,
			}},
		}

		validationResult, err := validator.VerifyVP(vp, nil)

		require.NoError(t, err)

		require.NotNil(t, validationResult)
	})

	t.Run("nok - invalid rawVP", func(t *testing.T) {
		validator := Service{}
		vp := vc.VerifiablePresentation{
			Proof: []interface{}{},
		}

		validationResult, err := validator.VerifyVP(vp, nil)

		assert.Nil(t, validationResult)
		assert.EqualError(t, err, "could not verify VP: invalid number of proofs, got 0, want 1")

	})
}

func TestIrmaVPVerificationResult(t *testing.T) {
	vr := irmaVPVerificationResult{
		validity: contract.Valid,
		vpType:   "type",
		disclosedAttributes: map[string]string{
			"gemeente.personalData.familyname": "tester",
			"gemeente.personalData.initials":   "i",
			"gemeente.personalData.prefix":     "von",
			"sidn-pbdf.email.email":            "info@example.com",
			"gemeente.personalData.digidlevel": "Midden",
		},
		contractAttributes: map[string]string{
			"a": "b",
		},
	}

	t.Run("attribute mapping", func(t *testing.T) {
		assert.Equal(t, "i", vr.DisclosedAttribute(services.InitialsTokenClaim))
		assert.Equal(t, "tester", vr.DisclosedAttribute(services.FamilyNameTokenClaim))
		assert.Equal(t, "von", vr.DisclosedAttribute(services.PrefixTokenClaim))
		assert.Equal(t, "info@example.com", vr.DisclosedAttribute(services.EmailTokenClaim))
		assert.Equal(t, "Midden", vr.DisclosedAttribute(services.EidasIALClaim))
	})

	t.Run("validity", func(t *testing.T) {
		assert.Equal(t, contract.Valid, vr.Validity())
	})

	t.Run("type", func(t *testing.T) {
		assert.Equal(t, "type", vr.VPType())
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
	}, crypto.NewMemoryCryptoInstance()
}
