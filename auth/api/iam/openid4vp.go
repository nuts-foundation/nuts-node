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
	"net/url"
	"strings"
	"time"
)

const sessionExpiry = 5 * time.Minute

// createPresentationRequest creates a new Authorization Request as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// It is sent by a verifier to a wallet, to request one or more verifiable credentials as verifiable presentation from the wallet.
func (r *Wrapper) sendPresentationRequest(ctx context.Context, response http.ResponseWriter, scope string,
	redirectURL url.URL, verifierIdentifier url.URL, walletIdentifier url.URL) error {
	// TODO: Lookup wallet metadata for correct authorization endpoint. But for Nuts nodes, we derive it from the walletIdentifier
	authzEndpoint := walletIdentifier.JoinPath("/authorize")
	params := make(map[string]string)
	params[scopeParam] = scope
	params[redirectURIParam] = redirectURL.String()
	// TODO: Check this
	params[clientMetadataURIParam] = verifierIdentifier.JoinPath("/.well-known/openid-wallet-metadata/metadata.xml").String()
	params[responseModeParam] = responseModeDirectPost
	params[responseTypeParam] = responseTypeVPIDToken
	// TODO: Depending on parameter size, we either use redirect with query parameters or a form post.
	//       For simplicity, we now just query parameters.
	result := AddQueryParams(*authzEndpoint, params)
	response.Header().Add("Location", result.String())
	response.WriteHeader(http.StatusFound)
	return nil
}

// handlePresentationRequest handles an Authorization Request as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// It is handled by a wallet, called by a verifier who wants the wallet to present one or more verifiable credentials.
func (r *Wrapper) handlePresentationRequest(params map[string]string, session *Session) (HandleAuthorizeRequestResponseObject, error) {
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
		RequiresUserIdentity: strings.Contains(session.ResponseType, "id_token"),
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

	submissionBuilder := presentationDefinition.PresentationSubmissionBuilder()
	submissionBuilder.AddWallet(session.OwnDID, ownCredentials)
	_, signInstructions, err := submissionBuilder.Build("ldp_vp")
	if err != nil {
		return nil, fmt.Errorf("unable to match presentation definition: %w", err)
	}
	var credentialIDs []string
	for _, signInstruction := range signInstructions {
		for _, matchingCredential := range signInstruction.VerifiableCredentials {
			templateParams.Credentials = append(templateParams.Credentials, makeCredentialInfo(matchingCredential))
			credentialIDs = append(credentialIDs, matchingCredential.ID.String())
		}
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
func (r *Wrapper) handlePresentationRequestAccept(c echo.Context) error {
	// TODO: Needs authentication?
	sessionID := c.FormValue("sessionID")
	if sessionID == "" {
		return errors.New("missing sessionID parameter")
	}

	var session Session
	sessionStore := r.storageEngine.GetSessionDatabase().GetStore(sessionExpiry, "openid", session.OwnDID.String(), "session")
	err := sessionStore.Get(sessionID, &session)
	if err != nil {
		return fmt.Errorf("invalid session: %w", err)
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
	presentationDefinition := r.auth.PresentationDefinitions().ByScope(session.Scope)
	if presentationDefinition == nil {
		return fmt.Errorf("unsupported scope for presentation exchange: %s", session.Scope)
	}
	// TODO: Options (including format)
	resultParams := map[string]string{}
	submissionBuilder := presentationDefinition.PresentationSubmissionBuilder()
	submissionBuilder.AddWallet(session.OwnDID, credentials)
	submission, signInstructions, err := submissionBuilder.Build("ldp_vp")
	if err != nil {
		return err
	}
	presentationSubmissionJSON, _ := json.Marshal(submission)
	resultParams[presentationSubmissionParam] = string(presentationSubmissionJSON)
	if len(signInstructions) != 1 {
		// todo support multiple wallets (org + user)
		return errors.New("expected to create exactly one presentation")
	}
	verifiablePresentation, err := r.vcr.Wallet().BuildPresentation(c.Request().Context(), signInstructions[0].VerifiableCredentials, holder.PresentationOptions{}, &signInstructions[0].Holder, false)
	if err != nil {
		return err
	}
	verifiablePresentationJSON, _ := verifiablePresentation.MarshalJSON()
	resultParams[vpTokenParam] = string(verifiablePresentationJSON)

	// TODO: check response mode, and submit accordingly (direct_post)
	return c.Redirect(http.StatusFound, session.CreateRedirectURI(resultParams))
}

func (r *Wrapper) handlePresentationRequestCompleted(ctx echo.Context) error {
	// TODO: response direct_post mode
	vpToken := ctx.QueryParams()[vpTokenParam]
	if len(vpToken) == 0 {
		// TODO: User-agent is a browser, need to render an HTML page
		return errors.New("missing parameter " + vpTokenParam)
	}
	vp := vc.VerifiablePresentation{}
	if err := vp.UnmarshalJSON([]byte(vpToken[0])); err != nil {
		// TODO: User-agent is a browser, need to render an HTML page
		return err
	}
	// TODO: verify signature and credentials of VP
	var credentials []CredentialInfo
	for _, cred := range vp.VerifiableCredential {
		credentials = append(credentials, makeCredentialInfo(cred))
	}
	buf := new(bytes.Buffer)
	if err := r.templates.ExecuteTemplate(buf, "openid4vp_demo_completed.html", struct {
		Credentials []CredentialInfo
	}{
		Credentials: credentials,
	}); err != nil {
		return err
	}
	return ctx.HTML(http.StatusOK, buf.String())
}

func assertParamPresent(params map[string]string, param ...string) error {
	for _, curr := range param {
		if len(params[curr]) == 0 {
			return fmt.Errorf("%s parameter must be present", curr)
		}
	}
	return nil
}

func assertParamNotPresent(params map[string]string, param ...string) error {
	for _, curr := range param {
		if len(params[curr]) > 0 {
			return fmt.Errorf("%s parameter must not be present", curr)
		}
	}
	return nil
}
