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

package irma

import (
	"errors"
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	irma "github.com/privacybydesign/irmago"
	irmaservercore "github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/assert"
)

func TestSessionPtr_MarshalJSON(t *testing.T) {
	s := SessionPtr{
		QrCodeInfo: irma.Qr{
			URL:  "url",
			Type: "type",
		},
		ID: "id",
	}
	js, err := s.MarshalJSON()

	assert.NoError(t, err)
	assert.Equal(t, "{\"clientPtr\":{\"u\":\"url\",\"irmaqr\":\"type\"},\"sessionID\":\"id\"}", string(js))
}

func TestSessionPtr_Payload(t *testing.T) {
	s := SessionPtr{
		QrCodeInfo: irma.Qr{
			URL:  "url",
			Type: "type",
		},
	}

	assert.Equal(t, "{\"u\":\"url\",\"irmaqr\":\"type\"}", string(s.Payload()))
}

func TestSessionPtr_SessionID(t *testing.T) {
	s := SessionPtr{
		ID: "id",
	}

	assert.Equal(t, "id", s.SessionID())
}

func TestService_StartSigningSession(t *testing.T) {
	correctContractText := "EN:PractitionerLogin:v3 I hereby declare to act on behalf of verpleeghuis De nootjes. This declaration is valid from maandag 1 oktober 12:00:00 until maandag 1 oktober 13:00:00."

	t.Run("error - malformed contract", func(t *testing.T) {
		service, ctrl := serviceWithMocks(t)
		defer ctrl.Finish()

		rawContractText := "not a contract"

		_, err := service.StartSigningSession(rawContractText)

		assert.Error(t, err)
	})

	t.Run("error - irma.StartSession returns error", func(t *testing.T) {
		service, ctrl := serviceWithMocks(t)
		defer ctrl.Finish()

		irmaMock := service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.err = errors.New("some error")

		_, err := service.StartSigningSession(correctContractText)

		assert.Error(t, err)
		assert.Equal(t, "error while creating session: some error", err.Error())
	})

	t.Run("ok", func(t *testing.T) {
		service, ctrl := serviceWithMocks(t)
		defer ctrl.Finish()

		irmaMock := service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.irmaQr = &irma.Qr{
			URL:  "url",
			Type: "type",
		}
		irmaMock.sessionToken = "token"

		session, err := service.StartSigningSession(correctContractText)

		assert.NoError(t, err)
		assert.Equal(t, "token", session.SessionID())
		assert.Equal(t, "{\"u\":\"url\",\"irmaqr\":\"type\"}", string(session.Payload()))
	})
}

func TestService_SigningSessionStatus(t *testing.T) {
	correctContractText := "EN:PractitionerLogin:v3 I hereby declare to act on behalf of verpleeghuis De nootjes. This declaration is valid from maandag 1 oktober 12:00:00 until maandag 1 oktober 13:00:00."

	t.Run("error - session not found", func(t *testing.T) {
		service, ctrl := serviceWithMocks(t)
		defer ctrl.Finish()

		irmaMock := service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = nil

		_, err := service.SigningSessionStatus("session")

		assert.Error(t, err)
		assert.Equal(t, services.ErrSessionNotFound, err)
	})

	t.Run("error - incorrect contract string", func(t *testing.T) {
		service, ctrl := serviceWithMocks(t)
		defer ctrl.Finish()

		irmaMock := service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = &irmaservercore.SessionResult{
			Token: "token",
			Signature: &irma.SignedMessage{
				Message: "not a contract",
			},
		}

		_, err := service.SigningSessionStatus("session")

		assert.Error(t, err)
		assert.Equal(t, "invalid contract text: could not extract contract version, language and type", err.Error())
	})

	t.Run("error - unknown org", func(t *testing.T) {
		t.Skip("Implement after we can look up orgs in contracts")
		service, ctrl := serviceWithMocks(t)
		defer ctrl.Finish()

		irmaMock := service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = &irmaservercore.SessionResult{
			Token: "token",
			Signature: &irma.SignedMessage{
				Message: correctContractText,
			},
		}
		//rMock := service.NameResolver.(*registryMock.MockRegistryClient)
		//rMock.EXPECT().ReverseLookup("verpleeghuis De nootjes").Return(nil, errors.New("some error"))

		_, err := service.SigningSessionStatus("session")

		assert.Error(t, err)
		assert.Equal(t, "could not create JWT for given session: some error", err.Error())
	})

	holder := *vdr.TestDIDA
	keyID := holder
	keyID.Fragment = keyID.ID

	t.Run("error - signing error", func(t *testing.T) {
		service, ctrl := serviceWithMocks(t)
		defer ctrl.Finish()

		irmaMock := service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = &irmaservercore.SessionResult{
			Token: "token",
			Signature: &irma.SignedMessage{
				Message: correctContractText,
			},
		}
		claims := map[string]interface{}{
			"iss":  holder.String(),
			"sig":  "eyJAY29udGV4dCI6IiIsInNpZ25hdHVyZSI6bnVsbCwiaW5kaWNlcyI6bnVsbCwibm9uY2UiOm51bGwsImNvbnRleHQiOm51bGwsIm1lc3NhZ2UiOiJFTjpQcmFjdGl0aW9uZXJMb2dpbjp2MyBJIGhlcmVieSBkZWNsYXJlIHRvIGFjdCBvbiBiZWhhbGYgb2YgdmVycGxlZWdodWlzIERlIG5vb3RqZXMuIFRoaXMgZGVjbGFyYXRpb24gaXMgdmFsaWQgZnJvbSBtYWFuZGFnIDEgb2t0b2JlciAxMjowMDowMCB1bnRpbCBtYWFuZGFnIDEgb2t0b2JlciAxMzowMDowMC4iLCJ0aW1lc3RhbXAiOm51bGx9",
			"type": "irma",
			"kid":  keyID.String(),
		}
		service.DIDResolver.(*types.MockResolver).EXPECT().ResolveSigningKeyID(holder, gomock.Any()).Return(keyID.String(), nil)
		service.Signer.(*crypto.MockJWTSigner).EXPECT().SignJWT(claims, gomock.Any()).Return("", errors.New("sign error"))

		_, err := service.SigningSessionStatus("session")

		assert.Error(t, err)
		assert.Equal(t, "sign error", err.Error())
	})

	t.Run("ok", func(t *testing.T) {
		service, ctrl := serviceWithMocks(t)
		defer ctrl.Finish()

		irmaMock := service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = &irmaservercore.SessionResult{
			Token:  "token",
			Status: "status",
			Signature: &irma.SignedMessage{
				Message: correctContractText,
			},
		}
		claims := map[string]interface{}{
			"iss":  holder.String(),
			"sig":  "eyJAY29udGV4dCI6IiIsInNpZ25hdHVyZSI6bnVsbCwiaW5kaWNlcyI6bnVsbCwibm9uY2UiOm51bGwsImNvbnRleHQiOm51bGwsIm1lc3NhZ2UiOiJFTjpQcmFjdGl0aW9uZXJMb2dpbjp2MyBJIGhlcmVieSBkZWNsYXJlIHRvIGFjdCBvbiBiZWhhbGYgb2YgdmVycGxlZWdodWlzIERlIG5vb3RqZXMuIFRoaXMgZGVjbGFyYXRpb24gaXMgdmFsaWQgZnJvbSBtYWFuZGFnIDEgb2t0b2JlciAxMjowMDowMCB1bnRpbCBtYWFuZGFnIDEgb2t0b2JlciAxMzowMDowMC4iLCJ0aW1lc3RhbXAiOm51bGx9",
			"type": "irma",
			"kid":  keyID.String(),
		}

		service.DIDResolver.(*types.MockResolver).EXPECT().ResolveSigningKeyID(holder, gomock.Any()).Return(keyID.String(), nil)
		service.Signer.(*crypto.MockJWTSigner).EXPECT().SignJWT(claims, keyID.String()).Return("jwt", nil)

		result, err := service.SigningSessionStatus("session")

		assert.NoError(t, err)
		assert.Equal(t, "status", result.Status())

		vp, err := result.VerifiablePresentation()

		assert.NoError(t, err)
		assert.NotNil(t, vp)
	})
}

func serviceWithMocks(t *testing.T) (*Service, *gomock.Controller) {
	serviceConfig := ValidatorConfig{
		IrmaConfigPath:        "../../../development/irma",
		AutoUpdateIrmaSchemas: false,
		IrmaSchemeManager:     "empty",
	}

	ctrl := gomock.NewController(t)

	irmaConfig, _ := GetIrmaConfig(serviceConfig)
	return &Service{
		IrmaSessionHandler: &mockIrmaClient{},
		IrmaConfig:         irmaConfig,
		DIDResolver:        types.NewMockResolver(ctrl),
		NameResolver:       vdr.NewMockNameResolver(ctrl),
		Signer:             crypto.NewMockJWTSigner(ctrl),
		ContractTemplates:  contract.StandardContractTemplates,
	}, ctrl
}
