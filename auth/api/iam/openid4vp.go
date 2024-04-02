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
	"github.com/lestrrat-go/jwx/v2/jwt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
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
	// check nonce
	// nonce in JWT must be present for signing to be unique for every request
	// we currently do not check the nonce against a nonce store, but we could do that in the future
	if params.get(oauth.NonceParam) == "" {
		return nil, withCallbackURI(oauthError(oauth.InvalidRequest, "missing nonce parameter"), redirectURL)
	}

	// GET authorization server metadata for wallet
	walletID := params.get(oauth.ClientIDParam)
	// the walletDID must be a did:web
	walletDID, err := did.ParseDID(walletID)
	if err != nil || walletDID.Method != "web" {
		return nil, withCallbackURI(oauthError(oauth.InvalidRequest, "invalid client_id parameter (only did:web is supported)"), redirectURL)
	}
	metadata, err := r.auth.IAMClient().AuthorizationServerMetadata(ctx, *walletDID)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, "failed to get metadata from wallet"), redirectURL)
	}
	// own generic endpoint
	ownURL, err := createOAuth2BaseURL(verifier)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.InvalidRequest, "invalid verifier DID"), redirectURL)
	}
	// generate presentation_definition_uri based on own presentation_definition endpoint + scope
	pdURL := ownURL.JoinPath("presentation_definition")
	presentationDefinitionURI := httpNuts.AddQueryParams(*pdURL, map[string]string{
		"scope": params.get(oauth.ScopeParam),
	})

	// redirect to wallet authorization endpoint, use direct_post mode
	// like this or as JAR (RFC9101):
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
	nonce := crypto.GenerateNonce()
	callbackURL := ownURL.JoinPath("response")
	metadataURL := ownURL.JoinPath(oauth.ClientMetadataPath)

	// check metadata for supported client_id_schemes
	if !slices.Contains(metadata.ClientIdSchemesSupported, didScheme) {
		return nil, withCallbackURI(oauthError(oauth.InvalidRequest, "wallet metadata does not contain did in client_id_schemes_supported"), redirectURL)
	}

	// create a client state for the verifier
	state := crypto.GenerateNonce()
	modifier := func(values map[string]interface{}) {
		values[oauth.ResponseTypeParam] = responseTypeVPToken
		values[clientIDSchemeParam] = didScheme
		values[responseURIParam] = callbackURL.String()
		values[presentationDefUriParam] = presentationDefinitionURI.String()
		values[clientMetadataURIParam] = metadataURL.String()
		values[responseModeParam] = responseModeDirectPost
		values[oauth.NonceParam] = nonce
		values[oauth.StateParam] = state
	}
	authServerURL, err := r.auth.IAMClient().CreateAuthorizationRequest(ctx, verifier, *walletDID, modifier)
	// TODO WIP: add PEX IDs completed to the storage, use server state for this
	openid4vpRequest := OAuthSession{
		ClientID:    walletID,
		Scope:       params.get(oauth.ScopeParam),
		OwnDID:      &verifier,
		ClientState: params.get(oauth.StateParam),
		RedirectURI: redirectURL.String(),
	}
	// use nonce and state to store authorization request in session store
	if err = r.oauthNonceStore().Put(nonce, openid4vpRequest); err != nil {
		return nil, oauth.OAuth2Error{Code: oauth.ServerError, Description: "failed to store server state"}
	}
	if err = r.oauthClientStateStore().Put(state, openid4vpRequest); err != nil {
		return nil, oauth.OAuth2Error{Code: oauth.ServerError, Description: "failed to store server state"}
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
// client_id_scheme, REQUIRED. This must be did
// clientMetadataURIParam, REQUIRED. This must be the verifier metadata endpoint
// nonce, REQUIRED.
// response_uri, REQUIRED. This must be the verifier node url
// response_mode, REQUIRED. Value MUST be "direct_post"
// presentation_definition_uri, REQUIRED. For getting the presentation definition

// there are way more error conditions that listed at: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-error-response
// missing or invalid parameters are all mapped to invalid_request
// any operation that fails is mapped to server_error, this includes unreachable or broken backends.
func (r Wrapper) handleAuthorizeRequestFromVerifier(ctx context.Context, walletDID did.DID, params oauthParameters) (HandleAuthorizeRequestResponseObject, error) {
	responseMode := params.get(responseModeParam)
	if responseMode != responseModeDirectPost {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "invalid response_mode parameter"}
	}

	// check the response URL because later errors will redirect to this URL
	responseURI := params.get(responseURIParam)
	if responseURI == "" {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "missing response_uri parameter"}
	}
	// we now have a valid responseURI, if we also have a clientState then the verifier can also redirect back to the original caller using its client state
	state := params.get(oauth.StateParam)
	if state == "" {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "missing state parameter"}
	}

	if params.get(clientIDSchemeParam) != didScheme {
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
	// get verifier metadata
	metadata, err := r.auth.IAMClient().ClientMetadata(ctx, params.get(clientMetadataURIParam))
	if err != nil {
		return r.sendAndHandleDirectPostError(ctx, oauth.OAuth2Error{Code: oauth.ServerError, Description: "failed to get client metadata (verifier)"}, responseURI, state)
	}
	// get presentation_definition from presentation_definition_uri
	presentationDefinitionURI := params.get(presentationDefUriParam)
	presentationDefinition, err := r.auth.IAMClient().PresentationDefinition(ctx, presentationDefinitionURI)
	if err != nil {
		return r.sendAndHandleDirectPostError(ctx, oauth.OAuth2Error{Code: oauth.InvalidPresentationDefinitionURI, Description: fmt.Sprintf("failed to retrieve presentation definition on %s", presentationDefinitionURI)}, responseURI, state)
	}

	// at this point in the flow it would be possible to ask the user to confirm the credentials to use

	// all params checked, delegate responsibility to the holder
	// todo expiration
	buildParams := holder.BuildParams{
		Audience: verifierDID.String(),
		Expires:  time.Now().Add(15 * time.Minute),
		Nonce:    nonce,
	}
	vp, submission, err := r.vcr.Wallet().BuildSubmission(ctx, walletDID, *presentationDefinition, metadata.VPFormats, buildParams)
	if err != nil {
		if errors.Is(err, holder.ErrNoCredentials) {
			return r.sendAndHandleDirectPostError(ctx, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "no credentials available"}, responseURI, state)
		}
		return r.sendAndHandleDirectPostError(ctx, oauth.OAuth2Error{Code: oauth.ServerError, Description: err.Error()}, responseURI, state)
	}

	// any error here is a server error, might need a fixup to prevent exposing to a user
	return r.sendAndHandleDirectPost(ctx, *vp, *submission, responseURI, state)
}

// sendAndHandleDirectPost sends OpenID4VP direct_post to the verifier. The verifier responds with a redirect to the client (including error fields if needed).
// If the direct post fails, the user-agent will be redirected back to the client with an error. (Original redirect_uri).
func (r Wrapper) sendAndHandleDirectPost(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI string, state string) (HandleAuthorizeRequestResponseObject, error) {
	redirectURI, err := r.auth.IAMClient().PostAuthorizationResponse(ctx, vp, presentationSubmission, verifierResponseURI, state)
	if err != nil {
		return nil, err
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

	if request.Body.VpToken == nil {
		return nil, oauthError(oauth.InvalidRequest, "missing vp_token")
	}

	pexEnvelope, err := pe.ParseEnvelope([]byte(*request.Body.VpToken))
	if err != nil || len(pexEnvelope.Presentations) == 0 {
		return nil, oauthError(oauth.InvalidRequest, "invalid vp_token")
	}

	// note: instead of using the challenge to lookup the oauth session, we could also add a client state from the verifier.
	// this would allow us to lookup the redirectURI without checking the VP first.

	// extract the nonce from the vp(s)
	nonce, err := extractChallenge(pexEnvelope.Presentations[0])
	if nonce == "" {
		return nil, oauthError(oauth.InvalidRequest, "failed to extract nonce from vp_token")
	}
	var oauthSession OAuthSession
	if err = r.oauthNonceStore().Get(nonce, &oauthSession); err != nil {
		return nil, oauthError(oauth.InvalidRequest, "invalid or expired nonce")
	}
	// any future error can be sent to the client using the redirectURI from the oauthSession
	callbackURI := oauthSession.redirectURI()

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

	// validate the presentation_submission against the presentation_definition (by scope)
	// the resulting credential map is stored and later used to generate the access token
	credentialMap, _, err := r.validatePresentationSubmission(ctx, *verifier, oauthSession.Scope, submission, pexEnvelope)
	if err != nil {
		return nil, withCallbackURI(err, callbackURI)
	}

	// check presence of the nonce and make sure the nonce is burned in the process.
	if err := r.validatePresentationNonce(pexEnvelope.Presentations); err != nil {
		return nil, withCallbackURI(err, callbackURI)
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

	// TODO WIP if not all PEX Ids have a submission, send another auth request with a new nonce

	// we take the existing OAuthSession and add the credential map to it
	// the credential map contains InputDescriptor.Id -> VC mappings
	// todo: use the InputDescriptor.Path to map the Id to Value@JSONPath since this will be later used to set the state for the access token
	oauthSession.ServerState = ServerState{}
	oauthSession.ServerState[credentialMapStateKey] = credentialMap
	oauthSession.ServerState[presentationsStateKey] = pexEnvelope.Presentations
	oauthSession.ServerState[submissionStateKey] = *submission

	authorizationCode := crypto.GenerateNonce()
	err = r.oauthCodeStore().Put(authorizationCode, oauthSession)
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
		oauth.CodeParam:  authorizationCode,
		oauth.StateParam: oauthSession.ClientState,
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

// validatePresentationNonce checks if the nonce is the same for all presentations.
// it deletes all nonces from the session store in the process.
// errors are returned as OAuth2 errors.
func (r Wrapper) validatePresentationNonce(presentations []vc.VerifiablePresentation) error {
	var nonce string
	var returnErr error
	for _, presentation := range presentations {
		nextNonce, err := extractChallenge(presentation)
		if nextNonce == "" {
			// fallback on nonce instead of challenge, todo: should be uniform, check vc data model specs for JWT/JSON-LD
			nextNonce, err = extractNonce(presentation)
			if nextNonce == "" {
				// error when all presentations are missing nonce's
				returnErr = oauth.OAuth2Error{
					Code:          oauth.InvalidRequest,
					InternalError: err,
					Description:   "presentation has invalid/missing nonce",
				}
			}
		}
		_ = r.oauthNonceStore().Delete(nextNonce)
		if nonce != "" && nonce != nextNonce {
			returnErr = oauth.OAuth2Error{
				Code:        oauth.InvalidRequest,
				Description: "not all presentations have the same nonce",
			}
		}
		nonce = nextNonce
	}

	return returnErr
}

func (r Wrapper) handleAccessTokenRequest(ctx context.Context, verifier did.DID, authorizationCode *string, redirectURI *string, clientId *string) (HandleTokenRequestResponseObject, error) {
	// first check redirectURI
	if redirectURI == nil {
		return nil, oauthError(oauth.InvalidRequest, "missing redirect_uri parameter")
	}
	callbackURI, err := url.Parse(*redirectURI)
	if err != nil {
		return nil, oauthError(oauth.InvalidRequest, "invalid redirect_uri parameter")
	}

	// check if the authorization code is valid
	var oauthSession OAuthSession
	err = r.oauthCodeStore().Get(*authorizationCode, &oauthSession)
	if err != nil {
		return nil, oauthError(oauth.InvalidRequest, "invalid authorization code")
	}

	// check if the redirectURI matches the one from the authorization request
	if oauthSession.redirectURI() != nil && oauthSession.redirectURI().String() != *redirectURI {
		return nil, withCallbackURI(oauthError(oauth.InvalidRequest, fmt.Sprintf("redirect_uri does not match: %s vs %s", oauthSession.RedirectURI, *redirectURI)), callbackURI)
	}

	// check if the client_id matches the one from the authorization request
	if oauthSession.ClientID != *clientId {
		return nil, withCallbackURI(oauthError(oauth.InvalidRequest, fmt.Sprintf("client_id does not match: %s vs %s", oauthSession.ClientID, *clientId)), callbackURI)
	}

	presentations := oauthSession.ServerState.VerifiablePresentations()
	submission := oauthSession.ServerState.PresentationSubmission()
	mapping, err := r.policyBackend.PresentationDefinitions(ctx, verifier, oauthSession.Scope)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("failed to fetch presentation definition: %s", err.Error())), callbackURI)
	}
	// todo, for now take the organization definition
	if _, ok := mapping[pe.WalletOwnerOrganization]; !ok {
		return nil, withCallbackURI(oauthError(oauth.ServerError, "no presentation definition found for organization wallet"), callbackURI)
	}
	credentialMap := oauthSession.ServerState.CredentialMap()
	subject, _ := did.ParseDID(oauthSession.ClientID)

	response, err := r.createAccessToken(verifier, time.Now(), presentations, submission, mapping[pe.WalletOwnerOrganization], oauthSession.Scope, *subject, credentialMap)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("failed to create access token: %s", err.Error())), callbackURI)
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
		return nil, oauthError(oauth.InvalidRequest, "invalid or expired state")
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
	tokenResponse, err := r.auth.IAMClient().AccessToken(ctx, *request.Params.Code, *oauthSession.VerifierDID, checkURL.String(), *oauthSession.OwnDID)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("failed to retrieve access token: %s", err.Error())), appCallbackURI)
	}
	// update TokenResponse using session.SessionID
	statusActive := oauth.AccessTokenRequestStatusActive
	tokenResponse.Status = &statusActive
	if err = r.accessTokenClientStore().Put(oauthSession.SessionID, tokenResponse); err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("failed to store access token: %s", err.Error())), appCallbackURI)
	}
	return Callback302Response{
		Headers: Callback302ResponseHeaders{Location: appCallbackURI.String()},
	}, nil
}

// createPresentationRequest creates a new Authorization Request as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// It is sent by a verifier to a wallet, to request one or more verifiable credentials as verifiable presentation from the wallet.
func (r Wrapper) sendPresentationRequest(_ context.Context, response http.ResponseWriter, scope string,
	redirectURL url.URL, verifierIdentifier url.URL, walletIdentifier url.URL) error {
	// TODO: Lookup wallet metadata for correct authorization endpoint. But for Nuts nodes, we derive it from the walletIdentifier
	authzEndpoint := walletIdentifier.JoinPath("/authorize")
	params := make(map[string]string)
	params[oauth.ScopeParam] = scope
	params[oauth.RedirectURIParam] = redirectURL.String()
	// TODO: Check this
	params[clientMetadataURIParam] = verifierIdentifier.JoinPath("/.well-known/openid-wallet-metadata/metadata.xml").String()
	params[responseModeParam] = responseModeDirectPost
	params[oauth.ResponseTypeParam] = responseTypeVPIDToken
	// TODO: Depending on parameter size, we either use redirect with query parameters or a form post.
	//       For simplicity, we now just query parameters.
	result := httpNuts.AddQueryParams(*authzEndpoint, params)
	response.Header().Add("Location", result.String())
	response.WriteHeader(http.StatusFound)
	return nil
}

// handlePresentationRequest handles an Authorization Request as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// It is handled by a wallet, called by a verifier who wants the wallet to present one or more verifiable credentials.
func (r Wrapper) handlePresentationRequest(ctx context.Context, params oauthParameters, session *OAuthSession) (HandleAuthorizeRequestResponseObject, error) {
	// Todo: for compatibility, we probably need to support presentation_definition and/or presentation_definition_uri.
	if err := assertParamNotPresent(params, presentationDefUriParam); err != nil {
		return nil, err
	}
	if err := assertParamPresent(params, presentationDefParam); err != nil {
		return nil, err
	}
	if err := assertParamPresent(params, oauth.ScopeParam); err != nil {
		return nil, err
	}
	if err := assertParamPresent(params, oauth.ResponseTypeParam); err != nil {
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
	if params.get(responseModeParam) != responseModeDirectPost {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "response_mode must be direct_post",
			RedirectURI: session.redirectURI(),
		}
	}

	presentationDefinition, err := pe.ParsePresentationDefinition([]byte(params.get(presentationDefParam)))
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: fmt.Sprintf("unsupported scope for presentation exchange: %s", params.get(oauth.ScopeParam)),
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

	credentials, err := r.vcr.Wallet().List(ctx, *session.OwnDID)
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
	submissionBuilder.AddWallet(*session.OwnDID, ownCredentials)
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

	credentials, err := r.vcr.Wallet().List(c.Request().Context(), *session.OwnDID)
	if err != nil {
		return err
	}
	presentationDefinition := session.PresentationDefinition
	// TODO: Options (including format)
	resultParams := map[string]string{}
	submissionBuilder := presentationDefinition.PresentationSubmissionBuilder()
	submissionBuilder.AddWallet(*session.OwnDID, credentials)
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

func assertParamPresent(params oauthParameters, param ...string) error {
	for _, curr := range param {
		if params.get(curr) == "" {
			return fmt.Errorf("%s parameter must be present", curr)
		}
	}
	return nil
}

func assertParamNotPresent(params oauthParameters, param ...string) error {
	for _, curr := range param {
		if params.get(curr) != "" {
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
