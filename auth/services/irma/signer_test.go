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

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
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
	correctContractText := "EN:PractitionerLogin:v3 I hereby declare to act on behalf of verpleeghuis De nootjes located in Caretown. This declaration is valid from maandag 1 oktober 12:00:00 until maandag 1 oktober 13:00:00."

	t.Run("error - malformed contract", func(t *testing.T) {
		ctx := serviceWithMocks(t)
		defer ctx.ctrl.Finish()

		rawContractText := "not a contract"

		_, err := ctx.service.StartSigningSession(rawContractText)

		assert.Error(t, err)
	})

	t.Run("error - irma.StartSession returns error", func(t *testing.T) {
		ctx := serviceWithMocks(t)
		defer ctx.ctrl.Finish()

		irmaMock := ctx.service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.err = errors.New("some error")

		_, err := ctx.service.StartSigningSession(correctContractText)

		assert.Error(t, err)
		assert.Equal(t, "error while creating session: some error", err.Error())
	})

	t.Run("ok", func(t *testing.T) {
		ctx := serviceWithMocks(t)
		defer ctx.ctrl.Finish()

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
		defer ctx.ctrl.Finish()

		irmaMock := ctx.service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = nil

		_, err := ctx.service.SigningSessionStatus("session")

		assert.Error(t, err)
		assert.Equal(t, services.ErrSessionNotFound, err)
	})

	t.Run("error - incorrect contract string", func(t *testing.T) {
		ctx := serviceWithMocks(t)
		defer ctx.ctrl.Finish()

		irmaMock := ctx.service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = &irmaservercore.SessionResult{
			Token: "token",
			Signature: &irma.SignedMessage{
				Message: "not a contract",
			},
		}

		_, err := ctx.service.SigningSessionStatus("session")

		assert.Error(t, err)
		assert.Equal(t, "invalid contract text: could not extract contract version, language and type", err.Error())
	})

	t.Run("error - unknown org", func(t *testing.T) {
		ctx := serviceWithMocks(t)
		defer ctx.ctrl.Finish()

		irmaMock := ctx.service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = &irmaservercore.SessionResult{
			Token: "token",
			Signature: &irma.SignedMessage{
				Message: correctContractText,
			},
		}
		ctx.conceptRegistry.EXPECT().QueryFor(concept.OrganizationConcept).Return(dummyQuery{}, nil)
		ctx.vcResolver.EXPECT().Search(gomock.Any()).Return([]vc.VerifiableCredential{}, nil)

		_, err := ctx.service.SigningSessionStatus("session")

		assert.Error(t, err)
		assert.Equal(t, "could not create JWT for given session: legalEntity not found", err.Error())
	})

	t.Run("error - org search returns error", func(t *testing.T) {
		ctx := serviceWithMocks(t)
		defer ctx.ctrl.Finish()

		irmaMock := ctx.service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = &irmaservercore.SessionResult{
			Token: "token",
			Signature: &irma.SignedMessage{
				Message: correctContractText,
			},
		}
		ctx.conceptRegistry.EXPECT().QueryFor(concept.OrganizationConcept).Return(dummyQuery{}, nil)
		ctx.vcResolver.EXPECT().Search(gomock.Any()).Return(nil, errors.New("b00m!"))

		_, err := ctx.service.SigningSessionStatus("session")

		assert.Error(t, err)
		assert.Equal(t, "could not create JWT for given session: b00m!", err.Error())
	})

	t.Run("error - missing concept", func(t *testing.T) {
		ctx := serviceWithMocks(t)
		defer ctx.ctrl.Finish()

		irmaMock := ctx.service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = &irmaservercore.SessionResult{
			Token: "token",
			Signature: &irma.SignedMessage{
				Message: correctContractText,
			},
		}
		ctx.conceptRegistry.EXPECT().QueryFor(concept.OrganizationConcept).Return(nil, concept.ErrUnknownConcept)

		_, err := ctx.service.SigningSessionStatus("session")

		assert.Error(t, err)
		assert.True(t, errors.Is(err, concept.ErrUnknownConcept))
	})

	t.Run("error - signing error", func(t *testing.T) {
		ctx := serviceWithMocks(t)
		defer ctx.ctrl.Finish()

		irmaMock := ctx.service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = &irmaservercore.SessionResult{
			Token: "token",
			Signature: &irma.SignedMessage{
				Message: correctContractText,
			},
		}
		ctx.conceptRegistry.EXPECT().QueryFor(concept.OrganizationConcept).Return(dummyQuery{}, nil)
		ctx.vcResolver.EXPECT().Search(gomock.Any()).Return([]vc.VerifiableCredential{concept.TestVC()}, nil)
		ctx.resolver.EXPECT().ResolveSigningKeyID(holder, gomock.Any()).Return(keyID.String(), nil)
		ctx.signer.EXPECT().SignJWT(gomock.Any(), gomock.Any()).Return("", errors.New("sign error"))

		_, err := ctx.service.SigningSessionStatus("session")

		assert.Error(t, err)
		assert.Equal(t, "sign error", err.Error())
	})

	t.Run("error - no vc.credentialSubject", func(t *testing.T) {
		ctx := serviceWithMocks(t)
		defer ctx.ctrl.Finish()

		irmaMock := ctx.service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = &irmaservercore.SessionResult{
			Token:  "token",
			Status: "status",
			Signature: &irma.SignedMessage{
				Message: correctContractText,
			},
		}

		ctx.conceptRegistry.EXPECT().QueryFor(concept.OrganizationConcept).Return(dummyQuery{}, nil)
		ctx.vcResolver.EXPECT().Search(gomock.Any()).Return([]vc.VerifiableCredential{{}}, nil)

		_, err := ctx.service.SigningSessionStatus("session")

		assert.Error(t, err)
		assert.Equal(t, "could not create JWT for given session: legalEntity not found", err.Error())
	})

	t.Run("ok", func(t *testing.T) {
		ctx := serviceWithMocks(t)
		defer ctx.ctrl.Finish()

		irmaMock := ctx.service.IrmaSessionHandler.(*mockIrmaClient)
		irmaMock.sessionResult = &irmaservercore.SessionResult{
			Token:  "token",
			Status: "status",
			Signature: &irma.SignedMessage{
				Message: correctContractText,
			},
		}
		claims := map[string]interface{}{
			"iss":  holder.String(),
			"sig":  "eyJAY29udGV4dCI6IiIsInNpZ25hdHVyZSI6bnVsbCwiaW5kaWNlcyI6bnVsbCwibm9uY2UiOm51bGwsImNvbnRleHQiOm51bGwsIm1lc3NhZ2UiOiJFTjpQcmFjdGl0aW9uZXJMb2dpbjp2MyBJIGhlcmVieSBkZWNsYXJlIHRvIGFjdCBvbiBiZWhhbGYgb2YgdmVycGxlZWdodWlzIERlIG5vb3RqZXMgbG9jYXRlZCBpbiBDYXJldG93bi4gVGhpcyBkZWNsYXJhdGlvbiBpcyB2YWxpZCBmcm9tIG1hYW5kYWcgMSBva3RvYmVyIDEyOjAwOjAwIHVudGlsIG1hYW5kYWcgMSBva3RvYmVyIDEzOjAwOjAwLiIsInRpbWVzdGFtcCI6bnVsbH0=",
			"type": "irma",
			"kid":  keyID.String(),
		}

		ctx.conceptRegistry.EXPECT().QueryFor(concept.OrganizationConcept).Return(dummyQuery{}, nil)
		ctx.vcResolver.EXPECT().Search(gomock.Any()).Return([]vc.VerifiableCredential{concept.TestVC()}, nil)
		ctx.resolver.EXPECT().ResolveSigningKeyID(holder, gomock.Any()).Return(keyID.String(), nil)
		ctx.signer.EXPECT().SignJWT(claims, keyID.String()).Return("jwt", nil)

		result, err := ctx.service.SigningSessionStatus("session")

		assert.NoError(t, err)
		assert.Equal(t, "status", result.Status())

		vp, err := result.VerifiablePresentation()

		assert.NoError(t, err)
		assert.NotNil(t, vp)
	})
}

type mockContext struct {
	ctrl            *gomock.Controller
	resolver        *types.MockResolver
	signer          *crypto.MockJWTSigner
	vcResolver      *vcr.MockResolver
	conceptRegistry *concept.MockRegistry
	service         *Service
}

func serviceWithMocks(t *testing.T) *mockContext {
	serviceConfig := ValidatorConfig{
		IrmaConfigPath:        "../../../development/irma",
		AutoUpdateIrmaSchemas: false,
		IrmaSchemeManager:     "empty",
	}

	ctrl := gomock.NewController(t)

	vcr := vcr.NewMockResolver(ctrl)
	conceptRegistry := concept.NewMockRegistry(ctrl)
	mockResolver := types.NewMockResolver(ctrl)
	mockSigner := crypto.NewMockJWTSigner(ctrl)
	vcr.EXPECT().Registry().Return(conceptRegistry).AnyTimes()

	irmaConfig, _ := GetIrmaConfig(serviceConfig)
	service := &Service{
		IrmaSessionHandler: &mockIrmaClient{},
		IrmaConfig:         irmaConfig,
		DIDResolver:        mockResolver,
		VCResolver:         vcr,
		Signer:             mockSigner,
		ContractTemplates:  contract.StandardContractTemplates,
	}

	return &mockContext{
		ctrl:            ctrl,
		resolver:        mockResolver,
		signer:          mockSigner,
		vcResolver:      vcr,
		conceptRegistry: conceptRegistry,
		service:         service,
	}
}

type dummyQuery struct{}

func (d dummyQuery) Concept() string {
	return "dummy"
}

func (d dummyQuery) Parts() []*concept.TemplateQuery {
	return []*concept.TemplateQuery{}
}

func (d dummyQuery) AddClause(_ concept.Clause) {

}
