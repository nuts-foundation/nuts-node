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
	irma "github.com/privacybydesign/irmago"
	irmaservercore "github.com/privacybydesign/irmago/server"
)

// TODO: Fix after implementing IRMA validator (https://github.com/nuts-foundation/nuts-node/issues/84)
//import (
//	"encoding/base64"
//	"encoding/json"
//	"errors"
//	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
//	core "github.com/nuts-foundation/nuts-go-core"
//	"github.com/nuts-foundation/nuts-node/auth/services"
//	"github.com/nuts-foundation/nuts-node/auth/testdata"
//	"github.com/nuts-foundation/nuts-node/crypto"
//	"github.com/nuts-foundation/nuts-node/vdr"
//	registryMock "github.com/nuts-foundation/nuts-registry/mock"
//	registry "github.com/nuts-foundation/nuts-registry/pkg"
//	"github.com/nuts-foundation/nuts-registry/pkg/db"
//	registryTest "github.com/nuts-foundation/nuts-registry/test"
//	"os"
//	"path"
//	"reflect"
//	"testing"
//	"time"
//
//	"github.com/nuts-foundation/nuts-node/auth/contract"
//
//	"github.com/nuts-foundation/nuts-go-test/io"
//
//	"github.com/nuts-foundation/nuts-auth/test"
//
//	"github.com/golang/mock/gomock"
//	irma "github.com/privacybydesign/irmago"
//	irmaservercore "github.com/privacybydesign/irmago/server"
//	"github.com/privacybydesign/irmago/server/irmaserver"
//	"github.com/spf13/cobra"
//	"github.com/stretchr/testify/assert"
//)
//
//func TestDefaultValidator_IsInitialized(t *testing.T) {
//	t.Run("No irma config returns false", func(t *testing.T) {
//		v := Service{}
//		assert.False(t, v.IsInitialized())
//	})
//
//	t.Run("with irma config returns true", func(t *testing.T) {
//		v := Service{IrmaConfig: &irma.Configuration{}}
//		assert.True(t, v.IsInitialized())
//	})
//}
//
//func TestValidateContract(t *testing.T) {
//	type args struct {
//		contract    string
//		format      services.ContractFormat
//		legalEntity string
//	}
//	location, _ := time.LoadLocation(contract.AmsterdamTimeZone)
//	tests := []struct {
//		name    string
//		args    args
//		date    time.Time
//		want    *services.ContractValidationResult
//		wantErr bool
//	}{
//		{
//			"a valid contract should be valid",
//			args{
//				base64.StdEncoding.EncodeToString([]byte(test.ValidIrmaContract)),
//				services.IrmaFormat,
//				"verpleeghuis De nootjes",
//			},
//			// contract is valid at 1 oct 2019 11:46:00
//			time.Date(2019, time.October, 1, 13, 46, 00, 0, location),
//			&services.ContractValidationResult{
//				ValidationResult:    services.Valid,
//				ContractFormat:      services.IrmaFormat,
//				DisclosedAttributes: map[string]string{"nuts.agb.agbcode": "00000007"},
//				ContractAttributes:  map[string]string{"legal_entity": "verpleeghuis De nootjes", "acting_party": "Demo EHR", "valid_from": "dinsdag, 1 oktober 2019 13:30:42", "valid_to": "dinsdag, 1 oktober 2019 14:30:42"},
//			},
//			false,
//		},
//		{
//			"an expired contract should be invalid",
//			args{
//				base64.StdEncoding.EncodeToString([]byte(test.ValidIrmaContract)),
//				services.IrmaFormat,
//				"legalEntity",
//			},
//			time.Date(2019, time.October, 2, 13, 46, 00, 0, location),
//			&services.ContractValidationResult{
//				ValidationResult:    services.Invalid,
//				ContractFormat:      services.IrmaFormat,
//				DisclosedAttributes: map[string]string{"nuts.agb.agbcode": "00000007"},
//			},
//			false,
//		},
//		{
//			"a forged contract should be invalid",
//			args{
//				base64.StdEncoding.EncodeToString([]byte(test.ForgedIrmaContract)),
//				services.IrmaFormat,
//				"legalEntity",
//			},
//			time.Date(2019, time.October, 1, 13, 46, 00, 0, location),
//			&services.ContractValidationResult{
//				ValidationResult: services.Invalid,
//				ContractFormat:   services.IrmaFormat,
//			},
//			false,
//		},
//		{
//			"a valid but unknown contract should give an error",
//			args{
//				base64.StdEncoding.EncodeToString([]byte(test.ValidUnknownIrmaContract)),
//				services.IrmaFormat,
//				"legalEntity",
//			},
//			time.Date(2019, time.May, 1, 16, 50, 00, 0, location),
//			nil,
//			true,
//		},
//		{
//			"a valid json string which is not a contract should give an error",
//			args{
//				base64.StdEncoding.EncodeToString([]byte(test.InvalidContract)),
//				services.IrmaFormat,
//				"legalEntity",
//			},
//			time.Now(), // the contract does not have a valid date
//			nil,
//			true,
//		},
//		{
//			"a random string should give an error",
//			args{
//				base64.StdEncoding.EncodeToString([]byte("some string which is not json")),
//				services.IrmaFormat,
//				"legalEntity",
//			},
//			time.Now(), // the contract does not have a valid date
//			nil,
//			true,
//		},
//		{
//			"an invalid base64 contract should give an error",
//			args{
//				"invalid base64",
//				services.IrmaFormat,
//				"legalEntity",
//			},
//			time.Now(), // the contract does not have a valid date
//			nil,
//			true,
//		},
//		{
//			"an unsupported format should give an error",
//			args{
//				base64.StdEncoding.EncodeToString([]byte(test.ValidIrmaContract)),
//				"UnsupportedFormat",
//				"legalEntity",
//			},
//			time.Now(), // the contract does not have a valid date
//			nil,
//			true,
//		},
//	}
//
//	authConfig := ValidatorConfig{
//		IrmaConfigPath:        "../../../testdata/irma",
//		AutoUpdateIrmaSchemas: true,
//	}
//
//	irmaConfig, _ := GetIrmaConfig(authConfig)
//	irmaServer, _ := GetIrmaServer(authConfig)
//	validator := Service{IrmaSessionHandler: irmaServer, IrmaConfig: irmaConfig, ContractTemplates: contract.StandardContractTemplates}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			got, err := validator.ValidateContract(tt.args.contract, tt.args.format, &tt.date)
//			if (err != nil) != tt.wantErr {
//				t.Errorf("ValidateContract() error = %v, wantErr %v", err, tt.wantErr)
//				return
//			}
//			if !reflect.DeepEqual(got, tt.want) {
//				t.Errorf("ValidateContract():\ngot:  %v\nwant: %v\n", got, tt.want)
//			}
//		})
//	}
//}
//
//func TestDefaultValidator_SessionStatus(t *testing.T) {
//	serviceConfig := ValidatorConfig{
//		IrmaConfigPath:        "../../../testdata/irma",
//		AutoUpdateIrmaSchemas: true,
//	}
//
//	signatureRequest := &irma.SignatureRequest{
//		Message: "Ik ga akkoord",
//		DisclosureRequest: irma.DisclosureRequest{
//			BaseRequest: irma.BaseRequest{
//				Type: irma.ActionSigning,
//			},
//			Disclose: irma.AttributeConDisCon{
//				irma.AttributeDisCon{
//					irma.AttributeCon{
//						irma.NewAttributeRequest("irma-demo.nuts.agb.agbcode"),
//					},
//				},
//			},
//		},
//	}
//
//	irmaServer, _ := GetIrmaServer(serviceConfig)
//	_, knownSessionID, _ := irmaServer.StartSession(signatureRequest, func(result *irmaservercore.SessionResult) {
//		logging.Log().Infof("session done, result: %s", irmaservercore.ToJson(result))
//	})
//
//	type fields struct {
//		IrmaServer *irmaserver.Server
//	}
//	type args struct {
//		id services.SessionID
//	}
//	irmaServer, _ = GetIrmaServer(serviceConfig)
//	tests := []struct {
//		name   string
//		fields fields
//		args   args
//		want   *services.SessionStatusResult
//	}{
//		{
//			"for an unknown session, it returns nil",
//			fields{irmaServer},
//			args{"unknown sessionId"},
//			nil,
//		},
//		{
//			"for a known session it returns a status",
//			fields{irmaServer},
//			args{services.SessionID(knownSessionID)},
//			&services.SessionStatusResult{
//				irmaservercore.SessionResult{Token: knownSessionID, Status: irmaservercore.StatusInitialized, Type: irma.ActionSigning},
//				"",
//			},
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			v := Service{
//				IrmaSessionHandler: tt.fields.IrmaServer,
//			}
//
//			got, _ := v.SessionStatus(tt.args.id)
//
//			if !reflect.DeepEqual(got, tt.want) {
//				t.Errorf("Service.SessionStatus() = %v, want %v", got, tt.want)
//			}
//		})
//	}
//}
//
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

func (m *mockIrmaClient) StartSession(request interface{}, handler irmaservercore.SessionHandler) (*irma.Qr, string, error) {
	if m.err != nil {
		return nil, "", m.err
	}

	return m.irmaQr, m.sessionToken, nil
}

//
//// tests using mocks
//func TestDefaultValidator_SessionStatus2(t *testing.T) {
//	serviceConfig := ValidatorConfig{
//		IrmaConfigPath:        "../../../testdata/irma",
//		AutoUpdateIrmaSchemas: true,
//	}
//
//	t.Run("correct contract with registry lookup", func(t *testing.T) {
//		ctrl := gomock.NewController(t)
//		keyResolver := vdr.NewMockDIDKeyResolver(ctrl)
//		jwtSigner := crypto.NewMockJWTSigner(ctrl)
//		nameResolver := vdr.NewMockNameResolver(ctrl)
//		iMock := mockIrmaClient{
//			sessionResult: &irmaservercore.SessionResult{
//				Token: "token",
//				Signature: &irma.SignedMessage{
//					Message: "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens verpleeghuis De nootjes en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42.",
//				},
//			},
//		}
//
//		irmaConfig, _ := GetIrmaConfig(serviceConfig)
//		v := Service{
//			IrmaSessionHandler: &iMock,
//			IrmaConfig:         irmaConfig,
//			DIDResolver:        keyResolver,
//			Signer:             jwtSigner,
//			NameResolver:       nameResolver,
//			ContractTemplates:  contract.StandardContractTemplates,
//		}
//
//		//orgID := registryTest.OrganizationID("1")
//		//rMock.EXPECT().ReverseLookup("verpleeghuis De nootjes").Return(&db.Organization{Identifier: orgID}, nil)
//		jwtSigner.EXPECT().SignJWT(gomock.Any(), "which key?").Return("token", nil)
//
//		s, err := v.SessionStatus("known")
//
//		if !assert.Nil(t, err) || !assert.NotNil(t, s) {
//			t.FailNow()
//		}
//		assert.Equal(t, "token", s.NutsAuthToken)
//	})
//}
//
//func TestDefaultValidator_ValidateJwt(t *testing.T) {
//
//	validator, cryptoInstance := defaultValidator(t)
//
//	t.Run("valid jwt", func(t *testing.T) {
//		token := createJwt(cryptoInstance, organizationID, organizationID, testdata.ValidIrmaContract)
//
//		checkTime, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
//		if err != nil {
//			return
//		}
//
//		result, err := validator.ValidateJwt(string(token), &checkTime)
//		if assert.NoError(t, err) && assert.NotNil(t, result) {
//			assert.Equal(t, services.ValidationState("VALID"), result.ValidationResult)
//			assert.Equal(t, services.ContractFormat("irma"), result.ContractFormat)
//			assert.Equal(t, map[string]string{"nuts.agb.agbcode": "00000007"}, result.DisclosedAttributes)
//		}
//	})
//
//	t.Run("missing legalEntity", func(t *testing.T) {
//		var payload services.NutsIdentityToken
//
//		var claims map[string]interface{}
//		jsonString, _ := json.Marshal(payload)
//		_ = json.Unmarshal(jsonString, &claims)
//
//		token, err := cryptoInstance.SignJWT(claims, cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: organizationID.String()}))
//		if err != nil {
//			return
//		}
//
//		checkTime, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
//		if err != nil {
//			return
//		}
//
//		result, err := validator.ValidateJwt(token, &checkTime)
//		if assert.Nil(t, result) && assert.NotNil(t, err) {
//			assert.EqualError(t, err, ErrLegalEntityNotProvided.Error())
//		}
//	})
//
//	t.Run("invalid formatted jwt", func(t *testing.T) {
//		token := "foo.bar.sig"
//
//		result, err := validator.ValidateJwt(token, nil, nil)
//
//		assert.Nil(t, result)
//		assert.Error(t, err)
//		assert.EqualError(t, err, "invalid character '~' looking for beginning of value")
//	})
//
//	t.Run("invalid signature", func(t *testing.T) {
//		token := createJwt(cryptoInstance, organizationID, organizationID, testdata.ForgedIrmaContract)
//
//		checkTime, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
//		if err != nil {
//			return
//		}
//
//		result, err := validator.ValidateJwt(string(token), nil, &checkTime)
//
//		if assert.NotNil(t, result) && assert.Nil(t, err) {
//			assert.Equal(t, services.Invalid, result.ValidationResult)
//		}
//	})
//
//	t.Run("wrong issuer", func(t *testing.T) {
//		token := createJwt(cryptoInstance, registryTest.OrganizationID("wrong_issuer"), organizationID, testdata.ValidIrmaContract)
//
//		result, err := validator.ValidateJwt(string(token), nil, nil)
//		assert.Nil(t, result)
//		assert.Error(t, err)
//		assert.Equal(t, "urn:oid:2.16.840.1.113883.2.4.6.1:wrong_issuer: organization not found", err.Error())
//	})
//
//	t.Run("wrong scheme manager", func(t *testing.T) {
//		os.Setenv("NUTS_STRICTMODE", "true")
//		cfg := core.NutsConfig()
//		if err := cfg.Load(&cobra.Command{}); err != nil {
//			t.Fatal("not expected error", err)
//		}
//
//		checkTime, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
//		if err != nil {
//			return
//		}
//
//		if assert.True(t, core.NutsConfig().InStrictMode()) {
//			token := createJwt(cryptoInstance, organizationID, organizationID, testdata.ValidIrmaContract)
//			result, err := validator.ValidateJwt(string(token), &checkTime)
//			if assert.NoError(t, err) && assert.NotNil(t, result) {
//				assert.Equal(t, services.ValidationState("INVALID"), result.ValidationResult)
//			}
//		}
//		os.Unsetenv("NUTS_STRICTMODE")
//	})
//}
//
//func TestDefaultValidator_createJwt(t *testing.T) {
//	t.Run("Create valid JWT", func(t *testing.T) {
//		validator, _ := defaultValidator(t)
//
//		var c = SignedIrmaContract{}
//		_ = json.Unmarshal([]byte(testdata.ValidIrmaContract), &c.IrmaContract)
//
//		tokenString, err := validator.CreateIdentityTokenFromIrmaContract(&c, organizationID)
//
//		checkTime, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
//		if err != nil {
//			return
//		}
//
//		if assert.Nil(t, err) && assert.NotEmpty(t, tokenString) {
//			result, err := validator.ValidateJwt(tokenString, &checkTime)
//			if assert.NoError(t, err) && assert.NotNil(t, result) {
//				assert.Equal(t, services.Valid, result.ValidationResult)
//			}
//		}
//	})
//}
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
//
//func TestService_VerifyVP(t *testing.T) {
//	t.Run("ok - valid VP", func(t *testing.T) {
//		validator, _ := defaultValidator(t)
//
//		irmaSignature := testdata.ValidIrmaContract
//		encodedIrmaSignature := base64.StdEncoding.EncodeToString([]byte(irmaSignature))
//
//		vp := VerifiablePresentation{
//			Proof: VPProof{
//				Proof:      contract.Proof{Type: ""},
//				ProofValue: encodedIrmaSignature,
//			},
//		}
//
//		rawIrmaVP, err := json.Marshal(vp)
//		if !assert.NoError(t, err) {
//			return
//		}
//		validationResult, err := validator.VerifyVP(rawIrmaVP, nil)
//
//		if !assert.NoError(t, err) {
//			return
//		}
//
//		if !assert.NotNil(t, validationResult) {
//			return
//		}
//	})
//
//	t.Run("nok - invalid rawVP", func(t *testing.T) {
//		validator := Service{}
//		validationResult, err := validator.VerifyVP([]byte{}, nil)
//
//		assert.Nil(t, validationResult)
//		if !assert.Error(t, err) {
//			return
//		}
//		assert.Equal(t, "could not verify VP: unexpected end of JSON input", err.Error())
//
//	})
//}
//
//func createJwt(cryptoInstance crypto.KeyStore, iss core.PartyID, sub core.PartyID, contractStr string) []byte {
//	contract := SignedIrmaContract{}
//	err := json.Unmarshal([]byte(contractStr), &contract.IrmaContract)
//	if err != nil {
//		panic(err)
//	}
//
//	encodedContract := base64.StdEncoding.EncodeToString([]byte(contractStr))
//
//	var payload services.NutsIdentityToken
//	payload.Issuer = iss.String()
//	payload.Type = services.IrmaFormat
//	payload.Subject = sub.String()
//	payload.Signature = encodedContract
//
//	jsonString, _ := json.Marshal(payload)
//	var claims map[string]interface{}
//	_ = json.Unmarshal(jsonString, &claims)
//
//	tokenString, _ := cryptoInstance.SignJWT(claims, "expected-key TODO")
//
//	return []byte(tokenString)
//}
//
//var organizationID = registryTest.OrganizationID("00000001")
//var otherOrganizationID = registryTest.OrganizationID("00000002")
//
//func defaultValidator(t *testing.T) (Service, crypto.KeyStore) {
//	t.Helper()
//	address := "localhost:1323"
//	serviceConfig := ValidatorConfig{
//		IrmaSchemeManager:     "empty",
//		AutoUpdateIrmaSchemas: true,
//		IrmaConfigPath:        "../../../development/irma",
//		PublicURL:             "http://" + address,
//	}
//
//	irmaConfig, err := GetIrmaConfig(serviceConfig)
//	if err != nil {
//		t.Fatal(err)
//	}
//	return Service{
//		IrmaConfig:        irmaConfig,
//		ContractTemplates: contract.StandardContractTemplates,
//	}, crypto.NewTestCryptoInstance(io.TestDirectory(t))
//}
