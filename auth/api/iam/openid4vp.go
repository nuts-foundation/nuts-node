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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/crypto"
	httpNuts "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/didjwk"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

var oauthNonceKey = []string{"oauth", "nonce"}

// handleAuthorizeRequestFromHolder handles an Authorization Request as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// we exclusively allow requests that use JAR (RFC9101, JWT Authorization Request).
// we expect a request like this:
// GET /iam/123/authorize?request=23987aer...2380957pASDFH HTTP/1.1
//
//	Host: server.com
//
// The following parameters are expected
// request, REQUIRED.  The request parameter value is a Request Object (JWT) that contains the request parameters.
// The JWT contains the following claims:
// iss, REQUIRED.  The issuer of the request.  The value MUST be a did:web.
// aud, REQUIRED.  The audience of the request.  The value MUST be a did:web.
// response_type, REQUIRED. Value MUST be set to "code".
// client_id, REQUIRED. This must be a did:web
// redirect_uri, REQUIRED. This must be the other node url
// scope, OPTIONAL. The scope that maps to a presentation definition, if not set we just want an empty VP
// state, RECOMMENDED.  Opaque value used to maintain state between the request and the callback.
// nonce, REQUIRED. Random value, may only be used once.
// code_challenge, REQUIRED.  Code challenge. (RFC7636)
// code_challenge_method, REQUIRED.  Code challenge method. (RFC7636)
func (r Wrapper) handleAuthorizeRequestFromHolder(ctx context.Context, verifier did.DID, params oauthParameters) (HandleAuthorizeRequestResponseObject, error) {
	// first we check the redirect URL because later errors will redirect to this URL
	// from RFC6749:
	// If the request fails due to a missing, invalid, or mismatching
	//   redirection URI, or if the client identifier is missing or invalid,
	//   the authorization server SHOULD inform the resource owner of the
	//   error and MUST NOT automatically redirect the user-agent to the
	//   invalid redirection URI.
	redirectURI := params.get(oauth.RedirectURIParam)
	if redirectURI == "" {
		// todo render error page instead of technical error
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "missing redirect_uri parameter"}
	}
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		// todo render error page instead of technical error (via errorWriter)
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "invalid redirect_uri parameter"}
	}
	// now we have a valid redirectURL, so all future errors will redirect to this URL using the Oauth2ErrorWriter

	// additional JAR checks
	// check if the audience is the verifier
	if params.get(jwt.AudienceKey) != verifier.String() {
		return nil, withCallbackURI(oauthError(oauth.InvalidRequest, fmt.Sprintf("invalid audience, verifier = %s, audience = %s", verifier.String(), params.get(jwt.AudienceKey))), redirectURL)
	}
	// we require PKCE (RFC7636) for authorization code flows
	// check code_challenge and code_challenge_method
	if params.get(oauth.CodeChallengeParam) == "" {
		return nil, oauthError(oauth.InvalidRequest, "missing code_challenge parameter")
	}
	if params.get(oauth.CodeChallengeMethodParam) == "" || params.get(oauth.CodeChallengeMethodParam) != "S256" {
		return nil, oauthError(oauth.InvalidRequest, "invalid value for code_challenge_method parameter, only S256 is supported")
	}

	// GET authorization server metadata for wallet
	walletID := params.get(oauth.ClientIDParam)
	// the walletDID must be a did:web
	walletDID, err := did.ParseDID(walletID)
	if err != nil || walletDID.Method != "web" {
		return nil, withCallbackURI(oauthError(oauth.InvalidRequest, "invalid client_id parameter (only did:web is supported)"), redirectURL)
	}
	oauthIssuer, err := didweb.DIDToURL(*walletDID)
	if err != nil {
		// can't fail since it's a valid did:web
		return nil, withCallbackURI(oauthError(oauth.InvalidRequest, "invalid client_id parameter (only did:web is supported)"), redirectURL)
	}
	metadata, err := r.auth.IAMClient().AuthorizationServerMetadata(ctx, oauthIssuer.String())
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, "failed to get metadata from wallet", err), redirectURL)
	}
	// check metadata for supported client_id_schemes
	if !slices.Contains(metadata.ClientIdSchemesSupported, didClientIDScheme) {
		return nil, withCallbackURI(oauthError(oauth.InvalidRequest, "wallet metadata does not contain did in client_id_schemes_supported"), redirectURL)
	}

	// Determine which PEX Presentation Definitions we want to see fulfilled during authorization through OpenID4VP.
	// Each Presentation Definition triggers 1 OpenID4VP flow.
	// TODO: Support multiple scopes?
	presentationDefinitions, err := r.presentationDefinitionForScope(ctx, verifier, params.get(oauth.ScopeParam))
	if err != nil {
		return nil, withCallbackURI(err, redirectURL)
	}

	session := OAuthSession{
		ClientID:          walletID,
		Scope:             params.get(oauth.ScopeParam),
		OwnDID:            &verifier,
		ClientState:       params.get(oauth.StateParam),
		RedirectURI:       redirectURL.String(),
		OpenID4VPVerifier: newPEXConsumer(presentationDefinitions),
		PKCEParams: PKCEParams{ // store params, when generating authorization code we take the params from the nonceStore and encrypt them in the authorization code
			Challenge:       params.get(oauth.CodeChallengeParam),
			ChallengeMethod: params.get(oauth.CodeChallengeMethodParam),
		},
	}
	// create a client state for the verifier
	state := crypto.GenerateNonce()
	if err = r.oauthClientStateStore().Put(state, session); err != nil {
		return nil, oauth.OAuth2Error{Code: oauth.ServerError, InternalError: err, Description: "failed to store server state"}
	}
	// Initiate OpenID4VP flow
	authServerURL, err := r.nextOpenID4VPFlow(ctx, state, session)
	if err != nil {
		return nil, err
	}
	return HandleAuthorizeRequest302Response{
		Headers: HandleAuthorizeRequest302ResponseHeaders{
			Location: authServerURL.String(),
		},
	}, nil
}

// nextOpenID4VPFlow sends the next OpenID4VP Authorization Request as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
// It returns the Authorization Request URL of the Authorization Server, to which the user agent should be redirected.
// Since authentication of the Resource Owner (e.g. as part of the Authorization Code flow) can consist of multiple OpenID4VP flows,
// this function checks whether all required Presentation Definitions are fulfilled.
// If there are more Presentation Definitions to fulfill, the next OpenID4VP Authorization Request is sent.
// If all Presentation Definitions are fulfilled, the OAuth2 session is completed. It then returns nil and no error.
func (r Wrapper) nextOpenID4VPFlow(ctx context.Context, state string, session OAuthSession) (*url.URL, error) {
	// Find next Presentation Definition to fulfill.
	walletOwnerType, _ := session.OpenID4VPVerifier.next()

	// own generic endpoint
	ownURL, err := createOAuth2BaseURL(*session.OwnDID)
	if err != nil {
		// impossible
		return nil, err
	}

	// generate presentation_definition_uri based on own presentation_definition endpoint + scope + wallet owner type
	pdURL := ownURL.JoinPath("presentation_definition")
	presentationDefinitionURI := httpNuts.AddQueryParams(*pdURL, map[string]string{
		"scope":             session.Scope,
		"wallet_owner_type": string(*walletOwnerType),
	})

	// redirect to wallet authorization endpoint, use direct_post mode
	// like this or as JAR (RFC9101):
	// GET /authorize?
	//    response_type=vp_token
	//    &client_id_scheme=did
	//    &client_metadata_uri=https%3A%2F%2Fexample.com%2Fiam%2F123%2F%2Fclient_metadata
	//    &client_id=did:web:example.com:iam:123
	//    &response_uri=https%3A%2F%2Fexample.com%2Fiam%2F123%2F%2Fresponse
	//    &presentation_definition_uri=...
	//    &response_mode=direct_post
	//    &nonce=n-0S6_WzA2Mj HTTP/1.1
	nonce := crypto.GenerateNonce()
	callbackURL := ownURL.JoinPath("response")
	metadataURL := ownURL.JoinPath(oauth.ClientMetadataPath)

	modifier := func(values map[string]string) {
		values[oauth.ResponseTypeParam] = oauth.VPTokenResponseType
		values[oauth.ClientIDSchemeParam] = didClientIDScheme
		values[oauth.ResponseURIParam] = callbackURL.String()
		values[oauth.PresentationDefUriParam] = presentationDefinitionURI.String()
		values[oauth.ClientMetadataURIParam] = metadataURL.String()
		values[oauth.ResponseModeParam] = responseModeDirectPost
		values[oauth.NonceParam] = nonce
		values[oauth.StateParam] = state
	}
	var authServerURL *url.URL
	if *walletOwnerType == pe.WalletOwnerUser {
		// User wallet, make an openid4vp: request URL
		authServerURL, err = r.createAuthorizationRequest(ctx, *session.OwnDID, nil, modifier)
	} else {
		walletDID, _ := did.ParseDID(session.ClientID)
		authServerURL, err = r.createAuthorizationRequest(ctx, *session.OwnDID, walletDID, modifier)
	}
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:          oauth.ServerError,
			Description:   "failed to authorize client",
			InternalError: fmt.Errorf("failed to generate authorization request URL: %w", err),
			RedirectURI:   session.redirectURI(),
		}
	}

	// use nonce and state to store authorization request in session store
	if err = r.oauthNonceStore().Put(nonce, state); err != nil {
		return nil, oauth.OAuth2Error{Code: oauth.ServerError, InternalError: err, Description: "failed to store server state"}
	}

	return authServerURL, nil
}

// handleAuthorizeRequestFromVerifier handles an Authorization Request for a wallet from a verifier as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// we expect an OpenID4VP request like this
// GET /iam/456/authorize?response_type=vp_token&client_id=did:web:example.com:iam:123&nonce=xyz
//        &response_mode=direct_post&response_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb&presentation_definition_uri=example.com%2Fiam%2F123%2Fpresentation_definition?scope=a+b HTTP/1.1
//    Host: server.com
// The following parameters are expected
// response_type, REQUIRED.  Value MUST be set to "vp_token".
// client_id, REQUIRED. This must be a did:web
// client_id_scheme, REQUIRED. This must be did
// client_metadata_uri, REQUIRED. This must be the verifier metadata endpoint
// nonce, REQUIRED.
// response_uri, REQUIRED. This must be the verifier node url
// response_mode, REQUIRED. Value MUST be "direct_post"
// presentation_definition_uri, REQUIRED. For getting the presentation definition

// there are way more error conditions that listed at: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-error-response
// missing or invalid parameters are all mapped to invalid_request
// any operation that fails is mapped to server_error, this includes unreachable or broken backends.
func (r Wrapper) handleAuthorizeRequestFromVerifier(ctx context.Context, tenantDID did.DID, params oauthParameters, walletOwnerType WalletOwnerType) (HandleAuthorizeRequestResponseObject, error) {
	responseMode := params.get(oauth.ResponseModeParam)
	if responseMode != responseModeDirectPost {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "invalid response_mode parameter"}
	}

	// check the response URL because later errors will redirect to this URL
	responseURI := params.get(oauth.ResponseURIParam)
	if responseURI == "" {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "missing response_uri parameter"}
	}
	// we now have a valid responseURI, if we also have a clientState then the verifier can also redirect back to the original caller using its client state
	state := params.get(oauth.StateParam)
	if state == "" {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "missing state parameter"}
	}

	if params.get(oauth.ClientIDSchemeParam) != didClientIDScheme {
		return r.sendAndHandleDirectPostError(ctx, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "invalid client_id_scheme parameter"}, responseURI, state)
	}

	verifierID := params.get(oauth.ClientIDParam)
	// the verifier must be a did:web
	verifierDID, err := did.ParseDID(verifierID)
	if err != nil || verifierDID.Method != "web" {
		return r.sendAndHandleDirectPostError(ctx, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "invalid client_id parameter (only did:web is supported)"}, responseURI, state)
	}

	nonce := params.get(oauth.NonceParam)
	if nonce == "" {
		return r.sendAndHandleDirectPostError(ctx, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "missing nonce parameter"}, responseURI, state)
	}

	// TODO: Create session if it does not exist (use client state to get original Authorization Code request)?
	//       Although it would be quite weird (maybe it expired).
	userSession, err := r.loadUserSession(ctx.Value(httpRequestContextKey{}).(*http.Request), tenantDID, nil)
	if userSession == nil {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, InternalError: err, Description: "no user session found"}
	}

	// get verifier metadata
	metadata, oauth2Err := r.getClientMetadataFromRequest(ctx, params)
	if oauth2Err != nil {
		return r.sendAndHandleDirectPostError(ctx, *oauth2Err, responseURI, state)
	}

	// get presentation_definition
	presentationDefinition, oauth2Err := r.getPresentationDefinitionFromRequest(ctx, params)
	if oauth2Err != nil {
		return r.sendAndHandleDirectPostError(ctx, *oauth2Err, responseURI, state)
	}

	// at this point in the flow it would be possible to ask the user to confirm the credentials to use

	// all params checked, delegate responsibility to the holder
	// todo expiration
	buildParams := holder.BuildParams{
		Audience: verifierDID.String(),
		Expires:  time.Now().Add(15 * time.Minute),
		Nonce:    nonce,
	}

	targetWallet := r.vcr.Wallet()
	walletDID := tenantDID
	if walletOwnerType == pe.WalletOwnerUser {
		// User wallet
		var privateKey jwk.Key
		privateKey, err = userSession.Wallet.Key()
		walletDID = userSession.Wallet.DID
		targetWallet = holder.NewMemoryWallet(
			r.JSONLDManager.DocumentLoader(),
			resolver.DIDKeyResolver{Resolver: didjwk.NewResolver()},
			crypto.MemoryJWTSigner{Key: privateKey},
			map[did.DID][]vc.VerifiableCredential{userSession.Wallet.DID: userSession.Wallet.Credentials},
		)
	}
	vp, submission, err := targetWallet.BuildSubmission(ctx, walletDID, *presentationDefinition, metadata.VPFormats, buildParams)
	if err != nil {
		if errors.Is(err, holder.ErrNoCredentials) {
			return r.sendAndHandleDirectPostError(ctx, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: fmt.Sprintf("no credentials available (PD ID: %s, wallet: %s)", presentationDefinition.Id, walletDID)}, responseURI, state)
		}
		return r.sendAndHandleDirectPostError(ctx, oauth.OAuth2Error{Code: oauth.ServerError, Description: err.Error()}, responseURI, state)
	}

	// any error here is a server error, might need a fixup to prevent exposing to a user
	return r.sendAndHandleDirectPost(ctx, userSession.Wallet.DID, *vp, *submission, responseURI, state)
}

func (r Wrapper) getClientMetadataFromRequest(ctx context.Context, params oauthParameters) (*oauth.OAuthClientMetadata, *oauth.OAuth2Error) {
	var metadata *oauth.OAuthClientMetadata
	var err error
	if metadataString := params.get(oauth.ClientMetadataParam); metadataString != "" {
		if params.get(oauth.ClientMetadataURIParam) != "" {
			return nil, &oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "client_metadata and client_metadata_uri are mutually exclusive", InternalError: err}
		}
		err = json.Unmarshal([]byte(metadataString), &metadata)
		if err != nil {
			return nil, &oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "invalid client_metadata", InternalError: err}
		}
	} else {
		metadata, err = r.auth.IAMClient().ClientMetadata(ctx, params.get(oauth.ClientMetadataURIParam))
		if err != nil {
			return nil, &oauth.OAuth2Error{Code: oauth.ServerError, Description: "failed to get client metadata (verifier)", InternalError: err}
		}
	}
	return metadata, nil
}

func (r Wrapper) getPresentationDefinitionFromRequest(ctx context.Context, params oauthParameters) (*pe.PresentationDefinition, *oauth.OAuth2Error) {
	var presentationDefinition *pe.PresentationDefinition
	var err error
	if pdString := params.get(oauth.PresentationDefParam); pdString != "" {
		if params.get(oauth.PresentationDefUriParam) != "" {
			return nil, &oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "presentation_definition and presentation_definition_uri are mutually exclusive"}
		}
		err = json.Unmarshal([]byte(pdString), &presentationDefinition)
		if err != nil {
			return nil, &oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "invalid presentation_definition", InternalError: err}
		}
	} else {
		presentationDefinitionURI := params.get(oauth.PresentationDefUriParam)
		presentationDefinition, err = r.auth.IAMClient().PresentationDefinition(ctx, presentationDefinitionURI)
		if err != nil {
			return nil, &oauth.OAuth2Error{Code: oauth.InvalidPresentationDefinitionURI, Description: fmt.Sprintf("failed to retrieve presentation definition on %s", presentationDefinitionURI), InternalError: err}
		}
	}
	return presentationDefinition, nil
}

// sendAndHandleDirectPost sends OpenID4VP direct_post to the verifier. The verifier responds with a redirect to the client (including error fields if needed).
// If the direct post fails, the user-agent will be redirected back to the client with an error. (Original redirect_uri).
func (r Wrapper) sendAndHandleDirectPost(ctx context.Context, userWalletDID did.DID, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI string, state string) (HandleAuthorizeRequestResponseObject, error) {
	redirectURI, err := r.auth.IAMClient().PostAuthorizationResponse(ctx, vp, presentationSubmission, verifierResponseURI, state)
	if err != nil {
		return nil, err
	}
	// Redirect URI starting with openid4vp: is a signal from the OpenID4VP verifier
	// that it requires another Verifiable Presentation, but this time from a user wallet.
	if strings.HasPrefix(redirectURI, "openid4vp:") {
		parsedRedirectURI, err := url.Parse(redirectURI)
		if err != nil {
			return nil, fmt.Errorf("verifier returned an invalid redirect URI: %w", err)
		}
		// Dispatch a new HTTP request to the local OpenID4VP wallet's authorization endpoint that includes request parameters,
		// but with openid4vp: as scheme.
		// The context contains data from the previous request. Usage by the handler will probably result in incorrect behavior.
		response, err := r.handleAuthorizeRequest(ctx, userWalletDID, *parsedRedirectURI)
		if err != nil {
			return nil, err
		}
		redirectURI = response.(HandleAuthorizeRequest302Response).Headers.Location
	}
	return HandleAuthorizeRequest302Response{
		HandleAuthorizeRequest302ResponseHeaders{
			Location: redirectURI,
		},
	}, nil
}

// sendAndHandleDirectPostError sends errors from handleAuthorizeRequestFromVerifier as direct_post to the verifier. The verifier responds with a redirect to the client (including error fields).
// If the direct post fails, the user-agent will be redirected back to the client with an error. (Original redirect_uri).
// If no redirect_uri is present, the user-agent will be redirected to the error page.
func (r Wrapper) sendAndHandleDirectPostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI string, verifierClientState string) (HandleAuthorizeRequestResponseObject, error) {
	redirectURI, err := r.auth.IAMClient().PostError(ctx, auth2Error, verifierResponseURI, verifierClientState)
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

func (r Wrapper) HandleAuthorizeResponse(ctx context.Context, request HandleAuthorizeResponseRequestObject) (HandleAuthorizeResponseResponseObject, error) {
	// this can be an error post or a submission. We check for the presence of the error parameter.
	if request.Body.Error != nil {
		return r.handleAuthorizeResponseError(ctx, request)
	}

	// successful response
	return r.handleAuthorizeResponseSubmission(ctx, request)
}

func (r Wrapper) handleAuthorizeResponseError(_ context.Context, request HandleAuthorizeResponseRequestObject) (HandleAuthorizeResponseResponseObject, error) {
	// we know error is not empty
	code := *request.Body.Error
	var description string
	if request.Body.ErrorDescription != nil {
		description = *request.Body.ErrorDescription
	}

	// check if the state param is present and if we have a client state for it
	var oauthSession OAuthSession
	if request.Body.State != nil {
		if err := r.oauthClientStateStore().Get(*request.Body.State, &oauthSession); err == nil {
			// we use the redirectURI from the oauthSession to redirect the user back to its own error page
			if oauthSession.redirectURI() != nil {
				location := httpNuts.AddQueryParams(*oauthSession.redirectURI(), map[string]string{
					oauth.ErrorParam:            code,
					oauth.ErrorDescriptionParam: description,
				})
				return HandleAuthorizeResponse200JSONResponse{
					RedirectURI: location.String(),
				}, nil
			}
		}
	}
	// we don't have a client state, so we can't redirect to the holder redirectURI
	// return an error page instead
	return nil, oauthError(oauth.ErrorCode(code), description)
}

func (r Wrapper) handleAuthorizeResponseSubmission(ctx context.Context, request HandleAuthorizeResponseRequestObject) (HandleAuthorizeResponseResponseObject, error) {
	verifier, err := r.toOwnedDIDForOAuth2(ctx, request.Did)
	if err != nil {
		return nil, oauthError(oauth.InvalidRequest, "unknown verifier id")
	}

	if request.Body.State == nil {
		return nil, oauthError(oauth.InvalidRequest, "missing state")
	}
	if request.Body.VpToken == nil {
		return nil, oauthError(oauth.InvalidRequest, "missing vp_token")
	}

	pexEnvelope, err := pe.ParseEnvelope([]byte(*request.Body.VpToken))
	if err != nil || len(pexEnvelope.Presentations) == 0 {
		return nil, oauthError(oauth.InvalidRequest, "invalid vp_token", err)
	}

	// Retrieve session through state, since we need to update it given the state.
	var session OAuthSession
	state := *request.Body.State
	if err = r.oauthClientStateStore().Get(state, &session); err != nil {
		return nil, oauthError(oauth.InvalidRequest, "invalid or expired session", err)
	}

	// any future error can be sent to the client using the redirectURI from the oauthSession
	// Also asserts that nonce and state reference the same OAuthSession.
	callbackURI := session.redirectURI()

	// check presence of the nonce and make sure the nonce is burned in the process.
	// Also asserts that nonce and state reference the same OAuthSession.
	if err = r.validatePresentationNonce(pexEnvelope.Presentations, state); err != nil {
		return nil, withCallbackURI(err, callbackURI)
	}

	if request.Body.PresentationSubmission == nil {
		return nil, oauthError(oauth.InvalidRequest, "missing presentation_submission")
	}
	submission, err := pe.ParsePresentationSubmission([]byte(*request.Body.PresentationSubmission))
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.InvalidRequest, fmt.Sprintf("invalid presentation_submission: %s", err.Error())), callbackURI)
	}

	// validate all presentations:
	// - same credentialSubject for VCs
	// - same audience for VPs
	// - same signer
	var credentialSubjectID did.DID
	for _, presentation := range pexEnvelope.Presentations {
		if subjectDID, err := validatePresentationSigner(presentation, credentialSubjectID); err != nil {
			return nil, withCallbackURI(oauthError(oauth.InvalidRequest, err.Error()), callbackURI)
		} else {
			credentialSubjectID = *subjectDID
		}
		if err := r.validatePresentationAudience(presentation, *verifier); err != nil {
			return nil, withCallbackURI(err, callbackURI)
		}
	}

	// Check signatures of VP and VCs. Trust should be established by the Presentation Definition.
	for _, presentation := range pexEnvelope.Presentations {
		_, err = r.vcr.Verifier().VerifyVP(presentation, true, true, nil)
		if err != nil {
			return nil, oauth.OAuth2Error{
				Code:          oauth.InvalidRequest,
				Description:   "presentation(s) or contained credential(s) are invalid",
				InternalError: err,
				RedirectURI:   callbackURI,
			}
		}
	}
	// we take the existing OAuthSession and add the credential map to it
	// todo: use the InputDescriptor.Path to map the Id to Value@JSONPath since this will be later used to set the state for the access token
	if err := session.OpenID4VPVerifier.fulfill(*submission, *pexEnvelope); err != nil {
		return nil, oauthError(oauth.InvalidRequest, err.Error())
	}
	if err = r.oauthClientStateStore().Put(state, session); err != nil {
		return nil, oauth.OAuth2Error{Code: oauth.ServerError, InternalError: err, Description: "failed to store server state"}
	}
	// See if there are more OpenID4VP flows to fulfill.
	// If all are completed, issue the authorization code.
	// If there are more flows, redirect to the next flow.
	nextWalletOwnerType, _ := session.OpenID4VPVerifier.next()
	if nextWalletOwnerType != nil {
		// More OpenID4VP flows to perform
		authServerURL, err := r.nextOpenID4VPFlow(ctx, state, session)
		if err != nil {
			return nil, err
		}
		return HandleAuthorizeResponse200JSONResponse{RedirectURI: authServerURL.String()}, nil
	}
	// Completed all OpenID4VP flows, issue the authorization code
	authorizationCode := crypto.GenerateNonce()
	err = r.oauthCodeStore().Put(authorizationCode, session)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:          oauth.ServerError,
			Description:   "failed to store authorization code",
			InternalError: err,
			RedirectURI:   callbackURI,
		}
	}

	// construct redirect URI according to RFC6749
	redirectURI := httpNuts.AddQueryParams(*callbackURI, map[string]string{
		oauth.CodeResponseType: authorizationCode,
		oauth.StateParam:       session.ClientState,
	})
	return HandleAuthorizeResponse200JSONResponse{RedirectURI: redirectURI.String()}, nil
}

func withCallbackURI(err error, callbackURI *url.URL) error {
	oauthErr := err.(oauth.OAuth2Error)
	oauthErr.RedirectURI = callbackURI
	return oauthErr
}

// extractChallenge extracts the nonce from the presentation.
// it uses the nonce from the JWT if available, otherwise it uses the challenge from the LD proof.
func extractChallenge(presentation vc.VerifiablePresentation) (string, error) {
	var nonce string
	switch presentation.Format() {
	case vc.JWTPresentationProofFormat:
		nonceRaw, _ := presentation.JWT().Get("nonce")
		nonce, _ = nonceRaw.(string)
	case vc.JSONLDPresentationProofFormat:
		proof, err := credential.ParseLDProof(presentation)
		if err != nil {
			return "", err
		}
		if proof.Challenge != nil && *proof.Challenge != "" {
			nonce = *proof.Challenge
		}
	}
	return nonce, nil
}

// validatePresentationNonce checks if the nonce is the same for all presentations
// it deletes all nonces from the session store in the process.
// errors are returned as OAuth2 errors.
func (r Wrapper) validatePresentationNonce(presentations []vc.VerifiablePresentation, state string) error {
	// we loop over all presentations and extract all nonces we can find.
	// Errors are accumulated until all presentations are checked.
	// If anything goes wrong, burn all nonces before returning an error.
	allPresent := true
	nonces := make([]string, 0, 1)
	var errs []error
	for _, presentation := range presentations {
		nonce, err := extractChallenge(presentation)
		if err != nil {
			errs = append(errs, err)
		}
		if nonce == "" {
			// fallback on nonce instead of challenge, todo: should be uniform, check vc data model specs for JWT/JSON-LD
			nonce, err = extractNonce(presentation)
			if err != nil {
				errs = append(errs, err)
			}
		}
		if nonce == "" {
			allPresent = false
		}
		if nonce != "" && !slices.Contains(nonces, nonce) {
			nonces = append(nonces, nonce)
		}
	}
	// accumulate all errors
	if len(nonces) > 1 {
		errs = append(errs, errors.New("not all presentations have the same nonce"))
	}
	if !allPresent { // also covers len(nonces) == 0
		errs = append(errs, errors.New("presentation is missing nonce"))
	}
	if len(errs) > 0 {
		// Something went wrong. We don't know what the real nonce is, so burn them all
		for _, nonce := range nonces {
			_ = r.oauthNonceStore().Delete(nonce)
		}
		return oauth.OAuth2Error{
			Code:          oauth.InvalidRequest,
			Description:   "invalid or missing nonce/challenge in presentation",
			InternalError: errors.Join(errs...),
		}
	}

	// check that the nonce belongs to this state
	// a sessions can have multiple flows with each its own nonce, so we have to use the mapping from nonce to state.
	var stateFromNonce string
	err := r.oauthNonceStore().GetAndDelete(nonces[0], &stateFromNonce)
	if err != nil {
		return oauthError(oauth.InvalidRequest, "invalid or expired session", err)
	}
	if state != stateFromNonce {
		return oauthError(oauth.InvalidRequest, "invalid nonce/state")
	}

	// nonce is valid and burned
	return nil
}

func (r Wrapper) handleAccessTokenRequest(ctx context.Context, request HandleTokenRequestFormdataRequestBody) (HandleTokenRequestResponseObject, error) {
	// check if code is present
	if request.Code == nil {
		return nil, oauthError(oauth.InvalidRequest, "missing code parameter")
	}
	defer func() {
		// a failing request could indicate a stolen authorization code. always burn a code once presented.
		_ = r.oauthCodeStore().Delete(*request.Code)
	}()
	// check if code_verifier is present
	if request.CodeVerifier == nil {
		return nil, oauthError(oauth.InvalidRequest, "missing code_verifier parameter")
	}
	// check if client_id is present
	if request.ClientId == nil {
		return nil, oauthError(oauth.InvalidRequest, "missing client_id parameter")
	}
	// check if the authorization code is valid
	var oauthSession OAuthSession
	err := r.oauthCodeStore().GetAndDelete(*request.Code, &oauthSession)
	if err != nil {
		return nil, oauthError(oauth.InvalidGrant, "invalid authorization code", err)
	}
	// check if the client_id matches the one from the authorization request
	if oauthSession.ClientID != *request.ClientId {
		return nil, oauthError(oauth.InvalidRequest, fmt.Sprintf("client_id does not match: %s vs %s", oauthSession.ClientID, *request.ClientId))
	}
	// check if the code_verifier is valid
	oauthSession.PKCEParams.Verifier = *request.CodeVerifier
	if !validatePKCEParams(oauthSession.PKCEParams) {
		return nil, oauthError(oauth.InvalidGrant, "invalid code_verifier")
	}

	// Parse optional DPoP header
	httpRequest := ctx.Value(httpRequestContextKey{}).(*http.Request)
	dpopProof, err := dpopFromRequest(*httpRequest)
	if err != nil {
		return nil, err
	}
	var submissions []PresentationSubmission
	for _, submission := range oauthSession.OpenID4VPVerifier.Submissions {
		submissions = append(submissions, submission)
	}
	presentationDefinitions := make([]PresentationDefinition, 0)
	for _, curr := range oauthSession.OpenID4VPVerifier.RequiredPresentationDefinitions {
		presentationDefinitions = append(presentationDefinitions, curr)
	}

	// All done, issue access token
	walletDID, err := did.ParseDID(oauthSession.ClientID)
	if err != nil {
		return nil, err
	}
	response, err := r.createAccessToken(*oauthSession.OwnDID, *walletDID, time.Now(), oauthSession.Scope, *oauthSession.OpenID4VPVerifier, dpopProof)
	if err != nil {
		return nil, oauthError(oauth.ServerError, fmt.Sprintf("failed to create access token: %s", err.Error()))
	}
	return HandleTokenRequest200JSONResponse(*response), nil
}

func (r Wrapper) handleCallbackError(request CallbackRequestObject) (CallbackResponseObject, error) {
	// we know error is not empty
	code := *request.Params.Error
	var description string
	if request.Params.ErrorDescription != nil {
		description = *request.Params.ErrorDescription
	}

	// check if the state param is present and if we have a client state for it
	var oauthSession OAuthSession
	if request.Params.State != nil {
		_ = r.oauthClientStateStore().Get(*request.Params.State, &oauthSession)
		// we use the redirectURI from the oauthSession to redirect the user back to its own error page
		if oauthSession.redirectURI() != nil {
			// add code and description
			location := httpNuts.AddQueryParams(*oauthSession.redirectURI(), map[string]string{
				oauth.ErrorParam:            code,
				oauth.ErrorDescriptionParam: description,
			})
			return Callback302Response{
				Headers: Callback302ResponseHeaders{Location: location.String()},
			}, nil
		}
	}
	// we don't have a client state, so we can't redirect to the holder redirectURI
	// return an error page instead
	return nil, oauthError(oauth.ErrorCode(code), description)
}

func (r Wrapper) handleCallback(ctx context.Context, request CallbackRequestObject) (CallbackResponseObject, error) {
	// check if state is present and resolves to a client state
	var oauthSession OAuthSession
	// return early with an OAuthError if state is nil
	if request.Params.State == nil {
		return nil, oauthError(oauth.InvalidRequest, "missing state parameter")
	}
	// lookup client state
	if err := r.oauthClientStateStore().Get(*request.Params.State, &oauthSession); err != nil {
		return nil, oauthError(oauth.InvalidRequest, "invalid or expired state", err)
	}
	// extract callback URI at calling app from OAuthSession
	// this is the URI where the user-agent will be redirected to
	appCallbackURI := oauthSession.redirectURI()

	// check if code is present
	if request.Params.Code == nil {
		return nil, withCallbackURI(oauthError(oauth.InvalidRequest, "missing code parameter"), appCallbackURI)
	}
	// send callback URL for verification (this method is the handler for that URL) to authorization server to check against earlier redirect_uri
	// we call it checkURL here because it is used by the authorization server to check if the code is valid
	requestHolder, _ := r.toOwnedDID(ctx, request.Did) // already checked
	checkURL, err := createOAuth2BaseURL(*requestHolder)
	if err != nil {
		return nil, fmt.Errorf("failed to create callback URL for verification: %w", err)
	}
	checkURL = checkURL.JoinPath(oauth.CallbackPath)

	// use code to request access token from remote token endpoint
	tokenResponse, err := r.auth.IAMClient().AccessToken(ctx, *request.Params.Code, oauthSession.TokenEndpoint, checkURL.String(), *oauthSession.OwnDID, oauthSession.PKCEParams.Verifier, oauthSession.UseDPoP)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("failed to retrieve access token: %s", err.Error())), appCallbackURI)
	}
	// update TokenResponse using session.SessionID
	tokenResponse = tokenResponse.With("status", oauth.AccessTokenRequestStatusActive)
	if err = r.accessTokenClientStore().Put(oauthSession.SessionID, tokenResponse); err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("failed to store access token: %s", err.Error())), appCallbackURI)
	}
	return Callback302Response{
		Headers: Callback302ResponseHeaders{Location: appCallbackURI.String()},
	}, nil
}

// oauthNonceStore is used to map nonce to state. Burn on use.
// This mapping is needed because we have one OAuthSession (state), but use a new nonce for every OpenID4VP flow.
func (r Wrapper) oauthNonceStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(oAuthFlowTimeout, oauthNonceKey...)
}

// oauthCodeStore is used to store the authorization server's OAuthSession in the authorization_code flow. Burn on use.
func (r Wrapper) oauthCodeStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(oAuthFlowTimeout, oauthCodeKey...)
}

func oauthError(code oauth.ErrorCode, description string, internalError ...error) oauth.OAuth2Error {
	return oauth.OAuth2Error{
		Code:          code,
		Description:   description,
		InternalError: errors.Join(internalError...),
	}
}
