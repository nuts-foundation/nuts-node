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
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/crypto"
	httpNuts "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"net/http"
	"net/url"
	"strings"
)

var oauthNonceKey = []string{"oauth", "nonce"}

func (r Wrapper) handleAuthorizeRequestFromHolder(ctx context.Context, verifier did.DID, params map[string]string) (HandleAuthorizeRequestResponseObject, error) {
	// we expect a generic OAuth2 request like this:
	// GET /iam/123/authorize?response_type=token&client_id=did:web:example.com:iam:456&state=xyz
	//        &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
	//    Host: server.com
	// The following parameters are expected
	// response_type, REQUIRED.  Value MUST be set to "token".
	// client_id, REQUIRED. This must be a did:web
	// redirect_uri, OPTIONAL. This must be the client or other node url (client for regular flow, node for popup)
	// scope, OPTIONAL. The scope that maps to a presentation definition, if not set we just want an empty VP
	// state, RECOMMENDED.  Opaque value used to maintain state between the request and the callback.

	// GET authorization server metadata for wallet
	walletID, ok := params[clientIDParam]
	if !ok {
		return nil, oauthError(oauth.InvalidRequest, "missing client_id parameter")
	}
	// the walletDID must be a did:web
	walletDID, err := did.ParseDID(walletID)
	if err != nil || walletDID.Method != "web" {
		return nil, oauthError(oauth.InvalidRequest, "invalid client_id parameter")
	}
	metadata, err := r.auth.RelyingParty().AuthorizationServerMetadata(ctx, *walletDID)
	if err != nil {
		return nil, oauthError(oauth.ServerError, "failed to get authorization server metadata (holder)")
	}
	// own generic endpoint
	ownURL, err := didweb.DIDToURL(verifier)
	if err != nil {
		return nil, oauthError(oauth.ServerError, "failed to translate own did to URL")
	}
	// generate presentation_definition_uri based on own presentation_definition endpoint + scope
	pdURL := ownURL.JoinPath("presentation_definition")
	presentationDefinitionURI := httpNuts.AddQueryParams(*pdURL, map[string]string{
		"scope": params[scopeParam],
	})

	// redirect to wallet authorization endpoint, use direct_post mode
	// like this:
	// GET /authorize?
	//    response_type=vp_token
	//    &client_id=did:web:example.com:iam:123
	//    &redirect_uri=https%3A%2F%2Fexample.com%2Fiam%2F123%2F%2Fresponse
	//    &presentation_definition_uri=...
	//    &response_mode=direct_post
	//    &nonce=n-0S6_WzA2Mj HTTP/1.1
	walletURL, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil || len(metadata.AuthorizationEndpoint) == 0 {
		return nil, oauthError(oauth.InvalidRequest, "invalid authorization_endpoint (holder)")
	}
	nonce := crypto.GenerateNonce()
	callbackURL := ownURL
	callbackURL.Path, err = url.JoinPath(callbackURL.Path, "response")
	if err != nil {
		return nil, oauthError(oauth.ServerError, "failed to construct redirect path")
	}

	redirectURL := httpNuts.AddQueryParams(*walletURL, map[string]string{
		responseTypeParam:       responseTypeVPToken,
		clientIDParam:           verifier.String(),
		redirectURIParam:        callbackURL.String(),
		presentationDefUriParam: presentationDefinitionURI.String(),
		responseModeParam:       responseModeDirectPost,
		nonceParam:              nonce,
	})
	openid4vpRequest := OAuthSession{
		ClientID:    verifier.String(),
		Scope:       params[scopeParam],
		OwnDID:      verifier,
		ClientState: nonce,
		RedirectURI: redirectURL.String(),
	}
	// use nonce to store authorization request in session store
	if err = r.oauthNonceStore().Put(nonce, openid4vpRequest); err != nil {
		return nil, oauthError(oauth.ServerError, "failed to store server state")
	}

	return HandleAuthorizeRequest302Response{
		Headers: HandleAuthorizeRequest302ResponseHeaders{
			Location: redirectURL.String(),
		},
	}, nil
}

// createPresentationRequest creates a new Authorization Request as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// It is sent by a verifier to a wallet, to request one or more verifiable credentials as verifiable presentation from the wallet.
func (r Wrapper) sendPresentationRequest(ctx context.Context, response http.ResponseWriter, scope string,
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
	result := httpNuts.AddQueryParams(*authzEndpoint, params)
	response.Header().Add("Location", result.String())
	response.WriteHeader(http.StatusFound)
	return nil
}

// handlePresentationRequest handles an Authorization Request as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// It is handled by a wallet, called by a verifier who wants the wallet to present one or more verifiable credentials.
func (r *Wrapper) handlePresentationRequest(params map[string]string, session *OAuthSession) (HandleAuthorizeRequestResponseObject, error) {
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
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "response_mode must be direct_post",
			RedirectURI: session.RedirectURI,
		}
	}

	// TODO: This is the easiest for now, but is this the way?
	// For compatibility, we probably need to support presentation_definition and/or presentation_definition_uri.
	presentationDefinition := r.auth.PresentationDefinitions().ByScope(params[scopeParam])
	if presentationDefinition == nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
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
func (r Wrapper) handlePresentationRequestAccept(c echo.Context) error {
	// TODO: Needs authentication?
	sessionID := c.FormValue("sessionID")
	if sessionID == "" {
		return errors.New("missing sessionID parameter")
	}

	var session OAuthSession
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

func (r Wrapper) handlePresentationRequestCompleted(ctx echo.Context) error {
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

func (r Wrapper) oauthNonceStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(oAuthFlowTimeout, oauthNonceKey...)
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

func oauthError(code oauth.ErrorCode, description string) oauth.OAuth2Error {
	return oauth.OAuth2Error{
		Code:        code,
		Description: description,
	}
}
