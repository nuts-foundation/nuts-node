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
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	oauthServices "github.com/nuts-foundation/nuts-node/auth/services/oauth"
	"github.com/nuts-foundation/nuts-node/crypto"
	httpNuts "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
)

var oauthNonceKey = []string{"oauth", "nonce"}

// handleAuthorizeRequestFromHolder handles an Authorization Request as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// we expect a generic OAuth2 request like this:
// GET /iam/123/authorize?response_type=token&client_id=did:web:example.com:iam:456&state=xyz
//
//	    &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
//	Host: server.com
//
// The following parameters are expected
// response_type, REQUIRED.  Value MUST be set to "code". (Already checked by caller)
// client_id, REQUIRED. This must be a did:web
// redirect_uri, REQUIRED. This must be the client or other node url (client for regular flow, node for popup)
// scope, OPTIONAL. The scope that maps to a presentation definition, if not set we just want an empty VP
// state, RECOMMENDED.  Opaque value used to maintain state between the request and the callback.
func (r Wrapper) handleAuthorizeRequestFromHolder(ctx context.Context, verifier did.DID, params map[string]string) (HandleAuthorizeRequestResponseObject, error) {
	// first we check the redirect URL because later errors will redirect to this URL
	// from RFC6749:
	// If the request fails due to a missing, invalid, or mismatching
	//   redirection URI, or if the client identifier is missing or invalid,
	//   the authorization server SHOULD inform the resource owner of the
	//   error and MUST NOT automatically redirect the user-agent to the
	//   invalid redirection URI.
	redirectURI, ok := params[redirectURIParam]
	if !ok {
		// todo render error page instead of technical error
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "missing redirect_uri parameter"}
	}
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		// todo render error page instead of technical error (via errorWriter)
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "invalid redirect_uri parameter"}
	}
	// now we have a valid redirectURL, so all future errors will redirect to this URL using the Oauth2ErrorWriter

	// GET authorization server metadata for wallet
	walletID := params[clientIDParam]
	// the walletDID must be a did:web
	walletDID, err := did.ParseDID(walletID)
	if err != nil || walletDID.Method != "web" {
		return nil, oauthError(oauth.InvalidRequest, "invalid client_id parameter (only did:web is supported)", redirectURL)
	}
	metadata, err := r.auth.Verifier().AuthorizationServerMetadata(ctx, *walletDID)
	if err != nil {
		return nil, oauthError(oauth.ServerError, "failed to get metadata from wallet", redirectURL)
	}
	// own generic endpoint
	ownURL, err := didweb.DIDToURL(verifier)
	if err != nil {
		return nil, oauthError(oauth.ServerError, "invalid verifier DID", redirectURL)
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
	//    &client_id_scheme=did
	//    &client_metadata_uri=https%3A%2F%2Fexample.com%2Fiam%2F123%2F%2Fclient_metadata
	//    &client_id=did:web:example.com:iam:123
	//    &client_id_scheme=did
	//    &client_metadata_uri=https%3A%2F%2Fexample.com%2F.well-known%2Fauthorization-server%2Fiam%2F123%2F%2F
	//    &response_uri=https%3A%2F%2Fexample.com%2Fiam%2F123%2F%2Fresponse
	//    &presentation_definition_uri=...
	//    &response_mode=direct_post
	//    &nonce=n-0S6_WzA2Mj HTTP/1.1
	walletURL, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil || len(metadata.AuthorizationEndpoint) == 0 {
		return nil, oauthError(oauth.InvalidRequest, "invalid wallet endpoint", redirectURL)
	}
	nonce := crypto.GenerateNonce()
	callbackURL := *ownURL
	callbackURL.Path, err = url.JoinPath(callbackURL.Path, "response")
	if err != nil {
		return nil, oauthError(oauth.ServerError, "failed to construct redirect path", redirectURL)
	}

	metadataURL, err := r.auth.Verifier().ClientMetadataURL(verifier)
	if err != nil {
		return nil, oauthError(oauth.ServerError, "failed to construct metadata URL", redirectURL)
	}

	// check metadata for supported client_id_schemes
	if !slices.Contains(metadata.ClientIdSchemesSupported, didScheme) {
		return nil, oauthError(oauth.InvalidRequest, "wallet metadata does not contain did in client_id_schemes_supported", redirectURL)
	}

	// todo: because of the did scheme, the request needs to be signed using JAR according to §5.7 of the openid4vp spec

	authServerURL := httpNuts.AddQueryParams(*walletURL, map[string]string{
		responseTypeParam:       responseTypeVPToken,
		clientIDSchemeParam:     didScheme,
		clientIDParam:           verifier.String(),
		responseURIParam:        callbackURL.String(),
		presentationDefUriParam: presentationDefinitionURI.String(),
		clientMetadataURIParam:  metadataURL.String(),
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
		return nil, oauthError(oauth.ServerError, "failed to store server state", redirectURL)
	}

	return HandleAuthorizeRequest302Response{
		Headers: HandleAuthorizeRequest302ResponseHeaders{
			Location: authServerURL.String(),
		},
	}, nil
}

// handleAuthorizeRequestFromVerifier handles an Authorization Request for a wallet from a verifier as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// we expect an OpenID4VP request like this
// GET /iam/456/authorize?response_type=vp_token&client_id=did:web:example.com:iam:123&nonce=xyz
//        &response_mode=direct_post&response_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb&presentation_definition_uri=example.com%2Fiam%2F123%2Fpresentation_definition?scope=a+b HTTP/1.1
//    Host: server.com
// The following parameters are expected
// response_type, REQUIRED.  Value MUST be set to "vp_token".
// client_id, REQUIRED. This must be a did:web
// response_uri, REQUIRED. This must be the verifier node url
// response_mode, REQUIRED. Value MUST be "direct_post"
// presentation_definition_uri, REQUIRED. For getting the presentation definition

// there are way more error conditions that listed at: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-error-response
// missing or invalid parameters are all mapped to invalid_request
// any operation that fails is mapped to server_error, this includes unreachable or broken backends.
func (r Wrapper) handleAuthorizeRequestFromVerifier(ctx context.Context, walletDID did.DID, params map[string]string) (HandleAuthorizeRequestResponseObject, error) {
	responseMode := params[responseModeParam]
	if responseMode != responseModeDirectPost {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "invalid response_mode parameter"}
	}
	// check the response URL because later errors will redirect to this URL
	responseURI, responseOK := params[responseURIParam]

	// get the original authorization request of the client, if something fails we need the redirectURI from this request
	// get the state parameter
	state, ok := params[stateParam]
	if !ok {
		// post error to responseURI, if it fails, it'll render error page
		return r.sendAndHandleDirectPostError(ctx, oauthError(oauth.InvalidRequest, "missing state parameter", nil), responseURI)
	}

	// check client state
	// if no state, post error
	var session OAuthSession
	err := r.oauthClientStateStore().Get(state, &session)
	if err != nil {
		if !responseOK {
			return nil, oauthError(oauth.ServerError, "something went wrong", nil)
		}
		return r.sendAndHandleDirectPostError(ctx, oauthError(oauth.InvalidRequest, "state has expired", nil), responseURI)
	}
	clientRedirectURL := session.redirectURI()
	if !responseOK {
		if clientRedirectURL != nil {
			return r.sendAndHandleDirectPostError(ctx, oauthError(oauth.InvalidRequest, "missing response_uri parameter", clientRedirectURL), clientRedirectURL.String())
		}
		return nil, oauthError(oauth.ServerError, "something went wrong", nil)
	}
	clientIDScheme := params[clientIDSchemeParam]
	if clientIDScheme != didScheme {
		return r.sendAndHandleDirectPostError(ctx, oauthError(oauth.InvalidRequest, "invalid client_id_scheme parameter", clientRedirectURL), responseURI)
	}
	verifierID := params[clientIDParam]
	// the verifier must be a did:web
	verifierDID, err := did.ParseDID(verifierID)
	if err != nil || verifierDID.Method != "web" {
		return r.sendAndHandleDirectPostError(ctx, oauthError(oauth.InvalidRequest, "invalid client_id parameter (only did:web is supported)", clientRedirectURL), responseURI)
	}
	nonce, ok := params[nonceParam]
	if !ok {
		return r.sendAndHandleDirectPostError(ctx, oauthError(oauth.InvalidRequest, "missing nonce parameter", clientRedirectURL), responseURI)
	}
	// get verifier metadata
	clientMetadataURI := params[clientMetadataURIParam]
	// we ignore any client_metadata, but officially an error must be returned when that param is present.
	metadata, err := r.auth.Holder().ClientMetadata(ctx, clientMetadataURI)
	if err != nil {
		return r.sendAndHandleDirectPostError(ctx, oauthError(oauth.ServerError, "failed to get client metadata (verifier)", clientRedirectURL), responseURI)
	}
	// get presentation_definition from presentation_definition_uri
	presentationDefinitionURI := params[presentationDefUriParam]
	presentationDefinition, err := r.auth.Holder().PresentationDefinition(ctx, presentationDefinitionURI)
	if err != nil {
		return r.sendAndHandleDirectPostError(ctx, oauthError(oauth.InvalidPresentationDefinitionURI, fmt.Sprintf("failed to retrieve presentation definition on %s", presentationDefinitionURI), clientRedirectURL), responseURI)
	}

	// at this point in the flow it would be possible to ask the user to confirm the credentials to use

	// all params checked, delegate responsibility to the holder
	vp, submission, err := r.auth.Holder().BuildPresentation(ctx, walletDID, *presentationDefinition, metadata.VPFormats, nonce)
	if err != nil {
		if errors.Is(err, oauthServices.ErrNoCredentials) {
			return r.sendAndHandleDirectPostError(ctx, oauthError(oauth.InvalidRequest, "no credentials available", clientRedirectURL), responseURI)
		}
		return r.sendAndHandleDirectPostError(ctx, oauthError(oauth.ServerError, err.Error(), clientRedirectURL), responseURI)
	}

	// any error here is a server error, might need a fixup to prevent exposing to a user
	return r.sendAndHandleDirectPost(ctx, *vp, *submission, responseURI, *clientRedirectURL, state), nil
}

// sendAndHandleDirectPost sends OpenID4VP direct_post to the verifier. The verifier responds with a redirect to the client (including error fields if needed).
// If the direct post fails, the user-agent will be redirected back to the client with an error. (Original redirect_uri).
func (r Wrapper) sendAndHandleDirectPost(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI string, clientRedirectURL url.URL, state string) HandleAuthorizeRequestResponseObject {
	redirectURI, err := r.auth.Holder().PostAuthorizationResponse(ctx, vp, presentationSubmission, verifierResponseURI, state)
	if err == nil {
		return HandleAuthorizeRequest302Response{
			HandleAuthorizeRequest302ResponseHeaders{
				Location: redirectURI,
			},
		}
	}

	msg := fmt.Sprintf("failed to post authorization response to verifier @ %s", verifierResponseURI)
	log.Logger().WithError(err).Error(msg)

	// clientRedirectURI has been checked earlier in te process.
	clientRedirectURL = httpNuts.AddQueryParams(clientRedirectURL, map[string]string{
		oauth.ErrorParam:            string(oauth.ServerError),
		oauth.ErrorDescriptionParam: msg,
	})
	return HandleAuthorizeRequest302Response{
		HandleAuthorizeRequest302ResponseHeaders{
			Location: clientRedirectURL.String(),
		},
	}
}

// sendAndHandleDirectPostError sends errors from handleAuthorizeRequestFromVerifier as direct_post to the verifier. The verifier responds with a redirect to the client (including error fields).
// If the direct post fails, the user-agent will be redirected back to the client with an error. (Original redirect_uri).
// If no redirect_uri is present, the user-agent will be redirected to the error page.
func (r Wrapper) sendAndHandleDirectPostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI string) (HandleAuthorizeRequestResponseObject, error) {
	redirectURI, err := r.auth.Holder().PostError(ctx, auth2Error, verifierResponseURI)
	if err == nil {
		return HandleAuthorizeRequest302Response{
			HandleAuthorizeRequest302ResponseHeaders{
				Location: redirectURI,
			},
		}, nil
	}

	msg := fmt.Sprintf("failed to post error to verifier @ %s", verifierResponseURI)
	log.Logger().WithError(err).Error(msg)

	if auth2Error.RedirectURI == nil {
		// render error page because all else failed, in a correct flow this should never happen
		// it could be the case that the client state has just expired, so no redirectURI is present and the verifier is not responding
		log.Logger().WithError(err).Error("failed to post error to verifier and no clientRedirectURI present")
		return nil, oauth.OAuth2Error{Code: oauth.ServerError, Description: "something went wrong"}
	}

	// clientRedirectURL has been checked earlier in te process.
	clientRedirectURL := httpNuts.AddQueryParams(*auth2Error.RedirectURI, map[string]string{
		oauth.ErrorParam:            string(oauth.ServerError),
		oauth.ErrorDescriptionParam: msg,
	})
	return HandleAuthorizeRequest302Response{
		HandleAuthorizeRequest302ResponseHeaders{
			Location: clientRedirectURL.String(),
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
func (r *Wrapper) handlePresentationRequest(ctx context.Context, params map[string]string, session *OAuthSession) (HandleAuthorizeRequestResponseObject, error) {
	// Todo: for compatibility, we probably need to support presentation_definition and/or presentation_definition_uri.
	if err := assertParamNotPresent(params, presentationDefUriParam); err != nil {
		return nil, err
	}
	if err := assertParamPresent(params, presentationDefParam); err != nil {
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
			RedirectURI: session.redirectURI(),
		}
	}

	presentationDefinition, err := pe.ParsePresentationDefinition([]byte(params[presentationDefParam]))
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: fmt.Sprintf("unsupported scope for presentation exchange: %s", params[scopeParam]),
			RedirectURI: session.redirectURI(),
		}
	}
	session.PresentationDefinition = *presentationDefinition

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

	credentials, err := r.vcr.Wallet().List(c.Request().Context(), session.OwnDID)
	if err != nil {
		return err
	}
	presentationDefinition := session.PresentationDefinition
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

func oauthError(code oauth.ErrorCode, description string, redirectURL *url.URL) oauth.OAuth2Error {
	return oauth.OAuth2Error{
		Code:        code,
		Description: description,
		RedirectURI: redirectURL,
	}
}
