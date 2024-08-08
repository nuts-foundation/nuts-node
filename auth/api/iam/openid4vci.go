/*
 * Copyright (C) 2024 Nuts community
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
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	nutsHttp "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

var timeFunc = time.Now

// jwtTypeOpenID4VCIProof defines the OpenID4VCI JWT-subtype (used as typ claim in the JWT).
const jwtTypeOpenID4VCIProof = "openid4vci-proof+jwt"

func (r Wrapper) RequestOpenid4VCICredentialIssuance(ctx context.Context, request RequestOpenid4VCICredentialIssuanceRequestObject) (RequestOpenid4VCICredentialIssuanceResponseObject, error) {
	if request.Body == nil {
		// why did oapi-codegen generate a pointer for the body??
		return nil, core.InvalidInputError("missing request body")
	}
	// Parse and check the requester
	requestHolder, err := r.selectDID(ctx, request.Subject)
	if err != nil {
		return nil, err
	}

	// Parse the issuer
	issuer := request.Body.Issuer
	if issuer == "" {
		return nil, core.InvalidInputError("issuer is empty")
	}
	// Fetch metadata containing the endpoints
	credentialIssuerMetadata, authzServerMetadata, err := r.openid4vciMetadata(ctx, request.Body.Issuer)
	if err != nil {
		return nil, core.Error(http.StatusFailedDependency, "cannot locate endpoints for %s: %w", issuer, err)
	}
	if len(credentialIssuerMetadata.CredentialEndpoint) == 0 {
		return nil, errors.New("no credential_endpoint found")
	}
	if len(authzServerMetadata.AuthorizationEndpoint) == 0 {
		return nil, errors.New("no authorization_endpoint found")
	}
	if len(authzServerMetadata.TokenEndpoint) == 0 {
		return nil, errors.New("no token_endpoint found")
	}
	// Read and parse the authorization details
	authorizationDetails := []byte("[]")
	if len(request.Body.AuthorizationDetails) > 0 {
		authorizationDetails, _ = json.Marshal(request.Body.AuthorizationDetails)
	}
	// Generate the state and PKCE
	state := crypto.GenerateNonce()
	pkceParams := generatePKCEParams()

	// Figure out our own redirect URL by parsing the did:web and extracting the host.
	redirectUri, err := createOAuth2BaseURL(*requestHolder)
	if err != nil {
		return nil, fmt.Errorf("failed to create callback URL for verification: %w", err)
	}
	redirectUri = redirectUri.JoinPath(oauth.CallbackPath)
	// Store the session
	err = r.oauthClientStateStore().Put(state, &OAuthSession{
		ClientFlow:  credentialRequestClientFlow,
		OwnDID:      requestHolder,
		RedirectURI: request.Body.RedirectUri,
		PKCEParams:  pkceParams,
		// OpenID4VCI issuers may use multiple Authorization Servers
		// We must use the token_endpoint that corresponds to the same Authorization Server used for the authorization_endpoint
		TokenEndpoint:            authzServerMetadata.TokenEndpoint,
		IssuerURL:                authzServerMetadata.Issuer,
		IssuerCredentialEndpoint: credentialIssuerMetadata.CredentialEndpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}
	// Build the redirect URL, the client browser should be redirected to.
	authorizationEndpoint, err := url.Parse(authzServerMetadata.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the authorization_endpoint: %w", err)
	}
	redirectUrl := nutsHttp.AddQueryParams(*authorizationEndpoint, map[string]string{
		oauth.ResponseTypeParam:         oauth.CodeResponseType,
		oauth.StateParam:                state,
		oauth.ClientIDParam:             requestHolder.String(),
		oauth.ClientIDSchemeParam:       didClientIDScheme,
		oauth.AuthorizationDetailsParam: string(authorizationDetails),
		oauth.RedirectURIParam:          redirectUri.String(),
		oauth.CodeChallengeParam:        pkceParams.Challenge,
		oauth.CodeChallengeMethodParam:  pkceParams.ChallengeMethod,
	})

	return RequestOpenid4VCICredentialIssuance200JSONResponse{
		RedirectURI: redirectUrl.String(),
	}, nil
}

func (r Wrapper) handleOpenID4VCICallback(ctx context.Context, authorizationCode string, oauthSession *OAuthSession) (CallbackResponseObject, error) {
	// extract callback URI at calling app from OAuthSession
	// this is the URI where the user-agent will be redirected to
	appCallbackURI := oauthSession.redirectURI()

	checkURL, err := createOAuth2BaseURL(*oauthSession.OwnDID)
	if err != nil {
		return nil, fmt.Errorf("failed to create callback URL for verification: %w", err)
	}
	checkURL = checkURL.JoinPath(oauth.CallbackPath)

	// use code to request access token from remote token endpoint
	response, err := r.auth.IAMClient().AccessToken(ctx, authorizationCode, oauthSession.TokenEndpoint, checkURL.String(), *oauthSession.OwnDID, oauthSession.PKCEParams.Verifier, false)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.AccessDenied, fmt.Sprintf("error while fetching the access_token from endpoint: %s, error: %s", oauthSession.TokenEndpoint, err.Error())), appCallbackURI)
	}

	// make proof and collect credential
	proofJWT, err := r.openid4vciProof(ctx, *oauthSession.OwnDID, oauthSession.IssuerURL, response.Get(oauth.CNonceParam))
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error building proof to fetch the credential from endpoint %s, error: %s", oauthSession.IssuerCredentialEndpoint, err.Error())), appCallbackURI)
	}
	credentials, err := r.auth.IAMClient().VerifiableCredentials(ctx, oauthSession.IssuerCredentialEndpoint, response.AccessToken, proofJWT)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while fetching the credential from endpoint %s, error: %s", oauthSession.IssuerCredentialEndpoint, err.Error())), appCallbackURI)
	}
	// validate credential
	// TODO: check that issued credential is bound to DID that requested it (OwnDID)???
	credential, err := vc.ParseVerifiableCredential(credentials.Credential)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while parsing the credential: %s, error: %s", credentials.Credential, err.Error())), appCallbackURI)
	}
	err = r.vcr.Verifier().Verify(*credential, true, true, nil)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while verifying the credential from issuer: %s, error: %s", credential.Issuer.String(), err.Error())), appCallbackURI)
	}
	// store credential in wallet
	err = r.vcr.Wallet().Put(ctx, *credential)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while storing credential with id: %s, error: %s", credential.ID, err.Error())), appCallbackURI)
	}
	return Callback302Response{
		Headers: Callback302ResponseHeaders{Location: appCallbackURI.String()},
	}, nil
}

func (r *Wrapper) openid4vciProof(ctx context.Context, holderDid did.DID, audience string, nonce string) (string, error) {
	kid, _, err := r.keyResolver.ResolveKey(holderDid, nil, resolver.AssertionMethod)
	if err != nil {
		return "", fmt.Errorf("failed to resolve key for did (%s): %w", holderDid.String(), err)
	}
	headers := map[string]interface{}{
		"typ": jwtTypeOpenID4VCIProof, // MUST be openid4vci-proof+jwt, which explicitly types the proof JWT as recommended in Section 3.11 of [RFC8725].
		"kid": kid,                    // JOSE Header containing the key ID. If the Credential shall be bound to a DID, the kid refers to a DID URL which identifies a particular key in the DID Document that the Credential shall be bound to.
	}
	if err != nil {
		// can't fail or would have failed before
		return "", err
	}
	claims := map[string]interface{}{
		jwt.IssuerKey:   holderDid.String(),
		jwt.AudienceKey: audience, // Credential Issuer Identifier
		jwt.IssuedAtKey: timeFunc().Unix(),
	}
	if nonce != "" {
		claims[oauth.NonceParam] = nonce
	}
	proofJwt, err := r.jwtSigner.SignJWT(ctx, claims, headers, kid)
	if err != nil {
		return "", fmt.Errorf("failed to sign the JWT with kid (%s): %w", kid, err)
	}
	return proofJwt, nil
}
