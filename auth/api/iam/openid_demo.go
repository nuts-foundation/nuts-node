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
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"net/http"
	"net/url"
	"strings"
)

func (r Wrapper) handleOpenIDDemoStart(echoCtx echo.Context) error {
	ownedDIDs, _ := r.vdr.ListOwned(echoCtx.Request().Context())
	buf := new(bytes.Buffer)
	if err := r.templates.ExecuteTemplate(buf, "openid_demo.html", struct {
		OwnedDIDs []did.DID
	}{
		OwnedDIDs: ownedDIDs,
	}); err != nil {
		return err
	}
	return echoCtx.HTML(http.StatusOK, buf.String())
}

func (r Wrapper) handleOpenIDDemoCompleted(c echo.Context) error {
	ownID := idToDID(c.Param("id"))
	_, session, err := r.getSessionFromParams(ownID, c.QueryParams())
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	var credentials []CredentialInfo
	if session.IDToken != nil {
		for _, cred := range session.IDToken.VerifiableCredential {
			credentials = append(credentials, makeCredentialInfo(cred))
		}
	}
	if session.VPToken != nil {
		for _, cred := range session.VPToken.VerifiableCredential {
			credentials = append(credentials, makeCredentialInfo(cred))
		}
	}
	buf := new(bytes.Buffer)
	if err := r.templates.ExecuteTemplate(buf, "openid_demo_completed.html", struct {
		Credentials []CredentialInfo
	}{
		Credentials: credentials,
	}); err != nil {
		return err
	}
	return c.HTML(http.StatusOK, buf.String())
}

func (r Wrapper) handleOpenID4VPDemoSendRequest(echoCtx echo.Context) error {
	verifierNutsDID, err := did.ParseDID(echoCtx.FormValue("verifier_did"))
	if err != nil {
		return fmt.Errorf("invalid verifier_did: %w", err)
	}
	var verifierWebDID *did.DID
	var verifierURL *url.URL
	if verifierNutsDID.Method == "nuts" {
		verifierURL = r.auth.PublicURL().JoinPath("iam", verifierNutsDID.ID)
		verifierWebDID, err = didweb.URLToDID(*verifierURL)
	} else {
		verifierURL = r.auth.PublicURL().JoinPath("iam", verifierNutsDID.String())
		verifierWebDID = verifierNutsDID
	}
	if err != nil {
		return fmt.Errorf("unable to convert did:nuts to web:did: %w", err)
	}
	scope := echoCtx.FormValue("scope")
	if scope == "" {
		return errors.New("missing scope")
	}
	scopes := strings.Split(scope, " ")

	// scope = openid && response_type == id_token -> SIOPv2

	// Render QR code
	session := Session{
		Scope:        scopes,
		OwnDID:       *verifierWebDID,
		ResponseType: []string{responseTypeIDToken},
	}
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
	sessionID := uuid.NewString()
	requestObject, err := r.createOpenIDAuthzRequest(echoCtx.Request().Context(), scope, sessionID, presentationDefinition,
		session.ResponseType, *verifierURL.JoinPath("authresponse"), *verifierWebDID)
	if err != nil {
		return fmt.Errorf("failed to create request object: %w", err)
	}
	session.RequestObject = requestObject
	if err := r.setSession(*verifierNutsDID, sessionID, session); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	requestURI := r.auth.PublicURL().JoinPath("iam", verifierNutsDID.ID, "openid", "request", sessionID)
	// openid-vc is JWT VC Presentation Profile scheme?
	qrCode := "openid-vc://?" + url.Values{"request_uri": []string{requestURI.String()}}.Encode()

	// Show QR code to scan using (mobile) wallet
	buf := new(bytes.Buffer)
	if err := r.templates.ExecuteTemplate(buf, "openid_demo_qrcode.html", struct {
		ID        string
		SessionID string
		QRCode    string
	}{
		ID:        verifierNutsDID.ID,
		SessionID: sessionID,
		QRCode:    qrCode,
	}); err != nil {
		return err
	}
	return echoCtx.HTML(http.StatusOK, buf.String())
}

func (r Wrapper) handleOpenID4VPDemoRequestWalletStatus(echoCtx echo.Context) error {
	ownDID := idToDID(echoCtx.Param("id"))
	// TODO: Needs authentication?
	session, err := r.getSessionByID(ownDID, echoCtx.FormValue("sessionID"))
	if err != nil {
		return err
	}
	if session.IDToken == nil {
		// No VP yet, keep polling
		return echoCtx.NoContent(http.StatusNoContent)
	}
	return echoCtx.JSON(http.StatusOK, session.IDToken)
}
