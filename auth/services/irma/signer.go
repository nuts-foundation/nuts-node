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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
	"strings"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/privacybydesign/irmago/server/irmaserver"

	"github.com/mdp/qrterminal/v3"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/services"
	irmago "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
)

// Signer signs contracts using the IRMA logic.
type Signer struct {
	sessionHandler signingSessionHandler
	schemeManager  string
	strictMode     bool
}

// SessionPtr should be made private when v0 is removed
type SessionPtr struct {
	ID         string
	QrCodeInfo irmago.Qr `json:"sessionPtr"`
}

// SessionID returns the SessionID of the SessionPtr
func (s SessionPtr) SessionID() string {
	return s.ID
}

// Payload renders the IrmaQRCode as json according to irmago.Qr
func (s SessionPtr) Payload() []byte {
	jsonResult, _ := json.Marshal(s.QrCodeInfo)
	return jsonResult
}

// MarshalJSON marshals a custom session pointer json object for the IRMA means.
func (s SessionPtr) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		QrCodeInfo irmago.Qr `json:"clientPtr"`
		ID         string    `json:"sessionID"`
	}{QrCodeInfo: s.QrCodeInfo, ID: s.ID})
}

// NutsIrmaSignedContract is the type of proof used in an Irma VP
const NutsIrmaSignedContract = "NutsIrmaSignedContract"

func (v Signer) Start(ctx context.Context) {
	return
}

// StartSigningSession accepts a rawContractText and creates an IRMA signing session.
func (v Signer) StartSigningSession(contract contract.Contract, _ map[string]interface{}) (contract.SessionPointer, error) {
	// Put the template in an IRMA envelope
	signatureRequest := irmago.NewSignatureRequest(contract.RawContractText)
	schemeManager := v.schemeManager

	var attributes irmago.AttributeCon
	for _, att := range contract.Template.SignerAttributes {
		// Checks if attribute name start with a dot, if so, add the configured scheme manager.
		if strings.Index(att, ".") == 0 {
			att = fmt.Sprintf("%s%s", schemeManager, att)
		}
		attributes = append(attributes, irmago.NewAttributeRequest(att))
	}
	signatureRequest.Disclose = irmago.AttributeConDisCon{
		irmago.AttributeDisCon{
			attributes,
		},
	}

	// Start an IRMA session
	sessionPointer, token, _, err := v.sessionHandler.StartSession(signatureRequest, func(result *server.SessionResult) {
		log.Logger().Debug("Session done")
		log.Logger().Trace(server.ToJson(result))
	})
	if err != nil {
		return nil, fmt.Errorf("error while creating session: %w", err)
	}
	log.Logger().Debug("Session created")
	log.Logger().Tracef("Token: %s", token)

	// Return the sessionPointer and sessionId
	challenge := SessionPtr{
		ID:         string(token),
		QrCodeInfo: *sessionPointer,
	}
	jsonResult := challenge.Payload()
	if log.Logger().Level >= logrus.DebugLevel {
		printQrCode(string(jsonResult))
	}
	log.Logger().Tracef("SessionPointer: %s", string(jsonResult))

	return challenge, nil
}

func (v Signer) Routes(router core.EchoRouter) {
	rewriteFunc := http.StripPrefix(IrmaMountPath, v.sessionHandler.HandlerFunc())
	irmaEchoHandler := echo.WrapHandler(rewriteFunc)
	methods := []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace}

	for _, method := range methods {
		router.Add(method, IrmaMountPath+"/*", irmaEchoHandler)
	}
}

// SigningSessionStatus returns the current status of a certain session.
// It returns nil if the session is not found
func (v Signer) SigningSessionStatus(_ context.Context, sessionID string) (contract.SigningSessionResult, error) {
	result, err := v.sessionHandler.GetSessionResult(irmago.RequestorToken(sessionID))
	if err != nil {
		if _, ok := err.(*irmaserver.UnknownSessionError); ok {
			return nil, services.ErrSessionNotFound
		}

		return nil, err
	}
	if result == nil {
		return nil, services.ErrSessionNotFound
	}

	return SigningSessionResult{SessionResult: *result}, nil
}

// SigningSessionResult implements the SigningSessionResult interface and contains the
// SigningSessionResult from the IRMA means.
type SigningSessionResult struct {
	server.SessionResult
}

// Status returns the IRMA signing status
func (s SigningSessionResult) Status() string {
	return string(s.SessionResult.Status)
}

// VerifiablePresentation returns an IRMA implementation of the contract.VerifiablePresentation interface.
func (s SigningSessionResult) VerifiablePresentation() (*vc.VerifiablePresentation, error) {

	irmaSig := s.Signature
	js, err := json.Marshal(irmaSig)
	if err != nil {
		return nil, fmt.Errorf("failed to create NutsIrmaPresentation: %w", err)
	}
	b64 := base64.StdEncoding.EncodeToString(js)

	return &vc.VerifiablePresentation{
		Context: []ssi.URI{vc.VCContextV1URI()},
		Type:    []ssi.URI{vc.VerifiablePresentationTypeV1URI(), ssi.MustParseURI(VerifiablePresentationType)},
		Proof: []interface{}{
			VPProof{
				Type:       NutsIrmaSignedContract,
				ProofValue: b64,
			},
		},
	}, nil
}

func printQrCode(qrcode string) {
	config := qrterminal.Config{
		HalfBlocks: false,
		BlackChar:  qrterminal.WHITE,
		WhiteChar:  qrterminal.BLACK,
		Level:      qrterminal.M,
		Writer:     os.Stdout,
		QuietZone:  1,
	}
	qrterminal.GenerateWithConfig(qrcode, config)
}

// signingSessionHandler is an abstraction for the Irma Server, mainly for enabling better testing
type signingSessionHandler interface {
	GetSessionResult(token irmago.RequestorToken) (*server.SessionResult, error)
	StartSession(request interface{}, handler server.SessionHandler) (*irmago.Qr, irmago.RequestorToken, *irmago.FrontendSessionRequest, error)
	HandlerFunc() http.HandlerFunc
}
