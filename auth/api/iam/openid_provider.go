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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"net/http"
	"slices"
)

// This file contains functions for the OpenID Provider (OP) role.

// handlePresentationRequest handles an Authorization Request as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// It is handled by a wallet, called by a verifier who wants the wallet to present one or more verifiable credentials.
func (r Wrapper) handlePresentationRequest(params map[string]string, session *Session) (HandleAuthorizeRequestResponseObject, error) {
	ctx := context.TODO()
	// Presentation definition is always derived from the scope.
	// Later on, we might support presentation_definition and/or presentation_definition_uri parameters instead of scope as well.
	if err := assertParamNotPresent(params, presentationDefParam, presentationDefUriParam); err != nil {
		return nil, err
	}
	if err := assertParamPresent(params, scopeParam); err != nil {
		return nil, err
	}
	if err := assertParamPresent(params, responseTypeParam); err != nil {
		return nil, err
	}
	// Not supported: client_id_schema, client_metadata
	if err := assertParamNotPresent(params, clientIDSchemeParam, clientMetadataParam); err != nil {
		return nil, err
	}
	// Required: client_metadata_uri
	if err := assertParamPresent(params, clientMetadataURIParam); err != nil {
		return nil, err
	}
	// Response mode is always direct_post for now
	if params[responseModeParam] != responseModeDirectPost {
		return nil, OAuth2Error{
			Code:        InvalidRequest,
			Description: "response_mode must be direct_post",
			RedirectURI: session.RedirectURI,
		}
	}

	// TODO: This is the easiest for now, but is this the way?
	// For compatibility, we probably need to support presentation_definition and/or presentation_definition_uri.
	presentationDefinition := r.auth.PresentationDefinitions().ByScope(params[scopeParam])
	if presentationDefinition == nil {
		return nil, OAuth2Error{
			Code:        InvalidRequest,
			Description: fmt.Sprintf("unsupported scope for presentation exchange: %s", params[scopeParam]),
			RedirectURI: session.RedirectURI,
		}
	}

	// Render HTML
	templateParams := struct {
		SessionID            string
		RequiresUserIdentity bool
		VerifierName         string
		Credentials          []CredentialInfo
	}{
		// TODO: Maybe this should the verifier name be read from registered client metadata?
		VerifierName:         ssi.MustParseURI(session.RedirectURI).Host,
		RequiresUserIdentity: slices.Contains(session.ResponseType, "id_token"),
	}

	// TODO: https://github.com/nuts-foundation/nuts-node/issues/2357
	// TODO: Retrieve presentation definition
	credentials, err := r.vcr.Wallet().List(ctx, session.OwnDID)
	if err != nil {
		return nil, err
	}
	var ownCredentials []vc.VerifiableCredential
	for _, cred := range credentials {
		var subject []credential.NutsOrganizationCredentialSubject
		if err = cred.UnmarshalCredentialSubject(&subject); err != nil {
			return nil, fmt.Errorf("unable to unmarshal credential: %w", err)
		}
		if len(subject) != 1 {
			continue
		}
		isOwner, _ := r.vdr.IsOwner(ctx, did.MustParseDID(subject[0].ID))
		if isOwner {
			ownCredentials = append(ownCredentials, cred)
		}
	}

	// TODO: https://github.com/nuts-foundation/nuts-node/issues/2359
	// TODO: What if multiple credentials of the same type match?
	_, matchingCredentials, err := presentationDefinition.Match(credentials)
	if err != nil {
		return nil, fmt.Errorf("unable to match presentation definition: %w", err)
	}
	var credentialIDs []string
	for _, matchingCredential := range matchingCredentials {
		templateParams.Credentials = append(templateParams.Credentials, makeCredentialInfo(matchingCredential))
		credentialIDs = append(credentialIDs, matchingCredential.ID.String())
	}
	session.ServerState["openid4vp_credentials"] = credentialIDs

	sessionID := uuid.NewString()
	err = r.storageEngine.GetSessionDatabase().GetStore(sessionExpiry, session.OwnDID.String(), "session").Put(sessionID, *session)
	if err != nil {
		return nil, err
	}
	templateParams.SessionID = sessionID

	// TODO: Support multiple languages
	buf := new(bytes.Buffer)
	err = r.templates.ExecuteTemplate(buf, "authz_wallet_en.html", templateParams)
	if err != nil {
		return nil, fmt.Errorf("unable to render authz page: %w", err)
	}
	return HandleAuthorizeRequest200TexthtmlResponse{
		Body:          buf,
		ContentLength: int64(buf.Len()),
	}, nil
}

// handleAuthConsent handles the authorization consent form submission.
func (r Wrapper) handlePresentationRequestAccept(c echo.Context) error {
	ownDID := idToDID(c.Param("id"))
	// TODO: Needs authentication?
	session, err := r.getSessionByID(ownDID, c.FormValue("sessionID"))
	if err != nil {
		return err
	}

	// TODO: Change to loading from wallet
	credentialIDs, ok := session.ServerState["openid4vp_credentials"].([]string)
	if !ok {
		return errors.New("invalid session (missing credentials in session)")
	}
	var credentials []vc.VerifiableCredential
	for _, id := range credentialIDs {
		credentialID, _ := ssi.ParseURI(id)
		if credentialID == nil {
			continue // should be impossible
		}
		cred, err := r.vcr.Resolve(*credentialID, nil)
		if err != nil {
			return err
		}
		credentials = append(credentials, *cred)
	}
	presentationDefinition := r.auth.PresentationDefinitions().ByScope(session.Scope[0]) // what about the others? Is this right?
	if presentationDefinition == nil {
		return fmt.Errorf("unsupported scope for presentation exchange: %s", session.Scope)
	}
	// TODO: Options
	resultParams := map[string]string{}
	presentationSubmission, credentials, err := presentationDefinition.Match(credentials)
	if err != nil {
		// Matched earlier, shouldn't happen
		return err
	}
	presentationSubmissionJSON, _ := json.Marshal(presentationSubmission)
	resultParams[presentationSubmissionParam] = string(presentationSubmissionJSON)
	verifiablePresentation, err := r.vcr.Wallet().BuildPresentation(c.Request().Context(), credentials, holder.PresentationOptions{}, &session.OwnDID, false)
	if err != nil {
		return err
	}
	verifiablePresentationJSON, _ := verifiablePresentation.MarshalJSON()
	resultParams[vpTokenParam] = string(verifiablePresentationJSON)

	// TODO: check response mode, and submit accordingly (direct_post)
	return c.Redirect(http.StatusFound, session.CreateRedirectURI(resultParams))
}
