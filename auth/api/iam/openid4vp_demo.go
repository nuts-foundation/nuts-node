/*
 * Copyright (C) 2023 Nuts community
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
 *
 */

package iam

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"net/http"
	"net/url"
)

type Protocol int

const (
	SIOPv2Protocol    Protocol = iota
	OpenID4VPProtocol Protocol = iota
)

func (r *Wrapper) handleOpenID4VPDemoLanding(echoCtx echo.Context) error {
	ownedDIDs, _ := r.vdr.ListOwned(echoCtx.Request().Context())
	if len(ownedDIDs) == 0 {
		return errors.New("no owned DIDs")
	}
	verifierID := r.auth.PublicURL().JoinPath("iam", ownedDIDs[0].ID).String()

	buf := new(bytes.Buffer)
	if err := r.templates.ExecuteTemplate(buf, "openid4vp_demo.html", struct {
		VerifierID string
		WalletID   string
	}{
		VerifierID: verifierID,
		WalletID:   verifierID,
	}); err != nil {
		return err
	}
	return echoCtx.HTML(http.StatusOK, buf.String())
}

func (r *Wrapper) handleOpenID4VPDemoSendRequest(echoCtx echo.Context) error {
	verifierID := echoCtx.FormValue("verifier_id")
	if verifierID == "" {
		return errors.New("missing verifier_id")
	}
	verifierURL, _ := url.Parse(verifierID)
	verifierDID, err := didweb.URLToDID(*verifierURL)
	if err != nil {
		return fmt.Errorf("invalid verifier DID: %w", err)
	}
	walletID := echoCtx.FormValue("wallet_id")
	if walletID == "" {
		return errors.New("missing wallet_id")
	}
	scope := echoCtx.FormValue("scope")
	if scope == "" {
		return errors.New("missing scope")
	}
	walletURL, _ := url.Parse(walletID)

	ctx := echoCtx.Request().Context()
	if echoCtx.Param("serverWallet") != "" {
		return r.sendPresentationRequest(
			ctx, echoCtx.Response(), scope,
			*walletURL.JoinPath("openid4vp_completed"), *verifierURL, *walletURL,
		)
	} else {
		// Render QR code
		session := Session{
			Scope:  scope,
			OwnDID: *verifierDID,
		}
		sessionID := r.sessions.Create(session)
		pePurpose := "For this demo you can provide any credential"
		pattern := "Sphereon Guest"
		presentationDefinition := pe.PresentationDefinition{
			Id:      "sphereon",
			Purpose: &pePurpose,
			InputDescriptors: []*pe.InputDescriptor{
				{
					Id:      uuid.NewString(),
					Name:    "Sphereon Guest",
					Purpose: "Any credential suffices",
					Schema: []map[string]interface{}{
						{
							"uri": "GuestCredential",
						},
					},
					Constraints: &pe.Constraints{
						Fields: []pe.Field{
							{
								Path: []string{
									"$.credentialSubject.type",
									"$.vc.credentialSubject.type",
								},
								Filter: &pe.Filter{
									Type:    "string",
									Pattern: &pattern,
								},
							},
						},
					},
				},
			},
		}
		requestObject, err := r.createOpenIDAuthzRequest(ctx, scope, sessionID, presentationDefinition,
			[]string{responseTypeIDToken}, *verifierURL.JoinPath("openid4vp_completed"), *verifierDID, verifierURL.Path)
		if err != nil {
			return fmt.Errorf("failed to create request object: %w", err)
		}
		session.RequestObject = requestObject
		r.sessions.Update(sessionID, session)

		requestURI := r.auth.PublicURL().JoinPath("iam", "openid4vp", "authzreq", sessionID)
		// openid-vc is JWT VC Presentation Profile scheme?
		qrCode := "openid-vc://?" + url.Values{"request_uri": []string{requestURI.String()}}.Encode()

		// Show QR code to scan using (mobile) wallet
		buf := new(bytes.Buffer)
		if err := r.templates.ExecuteTemplate(buf, "openid4vp_demo_qrcode.html", struct {
			SessionID string
			QRCode    string
		}{
			SessionID: sessionID,
			QRCode:    qrCode,
		}); err != nil {
			return err
		}
		return echoCtx.HTML(http.StatusOK, buf.String())
	}
}

func (r *Wrapper) handleOpenID4VPDemoGetRequestURI(echoCtx echo.Context) error {
	sessionID := echoCtx.Param("sessionID")
	if sessionID == "" {
		return echoCtx.JSON(http.StatusBadRequest, "missing sessionID")
	}
	session := r.sessions.Get(sessionID)
	if session == nil {
		return echoCtx.JSON(http.StatusNotFound, "unknown session")
	}
	return echoCtx.Blob(http.StatusOK, "text/plain", []byte(session.RequestObject))
}

func (r *Wrapper) handleOpenID4VPDemoRequestWalletStatus(echoCtx echo.Context) error {
	sessionID := echoCtx.FormValue("sessionID")
	if sessionID == "" {
		return echoCtx.JSON(http.StatusBadRequest, "missing sessionID")
	}
	session := r.sessions.Get(sessionID)
	if session == nil {
		return echoCtx.JSON(http.StatusNotFound, "unknown session")
	}
	if session.Presentation == nil {
		// No VP yet, keep polling
		return echoCtx.NoContent(http.StatusNoContent)
	}
	return echoCtx.JSON(http.StatusOK, session.Presentation)
}
