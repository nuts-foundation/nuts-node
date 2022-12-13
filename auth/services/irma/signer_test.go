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

	"github.com/privacybydesign/irmago/server/irmaserver"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr"

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
	correctContractText := "EN:PractitionerLogin:v3 I hereby declare to act on behalf of verpleeghuis De nootjes located in Caretown. This declaration is valid from maandag 1 oktober 12:00:00 until maandag 1 oktober 13:00:00."

	t.Run("error - malformed contract", func(t *testing.T) {
		ctx := serviceWithMocks(t)

		rawContractText := "not a contract"

		_, err := ctx.service.StartSigningSession(rawContractText)

		assert.Error(t, err)
	})

	t.Run("error - irma.StartSession returns error", func(t *testing.T) {
		ctx := serviceWithMocks(t)

		irmaMock := ctx.service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.err = errors.New("some error")

		_, err := ctx.service.StartSigningSession(correctContractText)

		assert.Error(t, err)
		assert.Equal(t, "error while creating session: some error", err.Error())
	})

	t.Run("ok", func(t *testing.T) {
		ctx := serviceWithMocks(t)

		irmaMock := ctx.service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.irmaQr = &irma.Qr{
			URL:  "url",
			Type: "type",
		}
		irmaMock.sessionToken = "token"

		session, err := ctx.service.StartSigningSession(correctContractText)

		assert.NoError(t, err)
		assert.Equal(t, "token", session.SessionID())
		assert.Equal(t, "{\"u\":\"url\",\"irmaqr\":\"type\"}", string(session.Payload()))
	})
}

func TestService_SigningSessionStatus(t *testing.T) {
	correctContractText := "EN:PractitionerLogin:v3 I hereby declare to act on behalf of verpleeghuis De nootjes located in Caretown. This declaration is valid from maandag 1 oktober 12:00:00 until maandag 1 oktober 13:00:00."
	holder := *vdr.TestDIDA
	keyID := holder
	keyID.Fragment = keyID.ID

	t.Run("error - session not found", func(t *testing.T) {
		ctx := serviceWithMocks(t)

		irmaMock := ctx.service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = nil
		irmaMock.err = &irmaserver.UnknownSessionError{}

		_, err := ctx.service.SigningSessionStatus("session")

		assert.Error(t, err)
		assert.Equal(t, services.ErrSessionNotFound, err)
	})

	t.Run("ok", func(t *testing.T) {
		ctx := serviceWithMocks(t)

		irmaMock := ctx.service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = &irmaservercore.SessionResult{
			Token:  "token",
			Status: "status",
			Signature: &irma.SignedMessage{
				Message: correctContractText,
			},
		}

		result, err := ctx.service.SigningSessionStatus("session")

		assert.NoError(t, err)
		assert.Equal(t, "status", result.Status())

		vp, err := result.VerifiablePresentation()

		assert.NoError(t, err)
		assert.NotNil(t, vp)
	})
}

type mockContext struct {
	ctrl       *gomock.Controller
	signer     *crypto.MockJWTSigner
	vcResolver *vcr.MockResolver
	service    *Service
}

func serviceWithMocks(t *testing.T) *mockContext {
	serviceConfig := ValidatorConfig{
		IrmaConfigPath:        "../../../development/irma",
		AutoUpdateIrmaSchemas: false,
		IrmaSchemeManager:     "empty",
	}

	ctrl := gomock.NewController(t)

	vcr := vcr.NewMockResolver(ctrl)
	mockSigner := crypto.NewMockJWTSigner(ctrl)

	irmaConfig, _ := GetIrmaConfig(serviceConfig)
	service := &Service{
		IrmaSessionHandler: &mockIrmaClient{},
		IrmaConfig:         irmaConfig,
		Signer:             mockSigner,
		ContractTemplates:  contract.StandardContractTemplates,
	}

	return &mockContext{
		ctrl:       ctrl,
		signer:     mockSigner,
		vcResolver: vcr,
		service:    service,
	}
}
