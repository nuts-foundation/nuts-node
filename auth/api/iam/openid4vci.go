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

	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	nutsHttp "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

func (r Wrapper) RequestOid4vciCredentialIssuance(ctx context.Context, request RequestOid4vciCredentialIssuanceRequestObject) (RequestOid4vciCredentialIssuanceResponseObject, error) {
	if request.Body == nil {
		// why did oapi-codegen generate a pointer for the body??
		return nil, core.InvalidInputError("missing request body")
	}
	// Parse and check the requester
	requestHolder, err := r.toOwnedDID(ctx, request.Did)
	if err != nil {
		return nil, core.NotFoundError("requester DID: %w", err)
	}

	// Parse the issuer
	issuerDid, err := did.ParseDID(request.Body.Issuer)
	if err != nil {
		return nil, core.InvalidInputError("could not parse Issuer DID: %s: %w", request.Body.Issuer, err)
	}
	// Fetch metadata containing the endpoints
	credentialIssuerMetadata, authzServerMetadata, err := r.openid4vciMetadata(ctx, *issuerDid)
	if err != nil {
		return nil, core.Error(http.StatusFailedDependency, "cannot locate endpoints for %s: %w", issuerDid.String(), err)
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
	requesterDidUrl, err := didweb.DIDToURL(*requestHolder)
	if err != nil {
		return nil, fmt.Errorf("failed convert did (%s) to url: %w", requestHolder.String(), err)
	}
	redirectUri, err := url.Parse(fmt.Sprintf("https://%s/iam/oid4vci/callback", requesterDidUrl.Host))
	if err != nil {
		return nil, fmt.Errorf("failed to create the url for host: %w", err)
	}
	// Store the session
	err = r.openid4vciSessionStore().Put(state, &Oid4vciSession{
		HolderDid:         requestHolder,
		IssuerDid:         issuerDid,
		RemoteRedirectUri: request.Body.RedirectUri,
		RedirectUri:       redirectUri.String(),
		PKCEParams:        pkceParams,
		// OpenID4VCI issuers may use multiple Authorization Servers
		// We must use the token_endpoint that corresponds to the same Authorization Server used for the authorization_endpoint
		IssuerTokenEndpoint:      authzServerMetadata.TokenEndpoint,
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
		oauth.AuthorizationDetailsParam: string(authorizationDetails),
		oauth.RedirectURIParam:          redirectUri.String(),
		oauth.CodeChallengeParam:        pkceParams.Challenge,
		oauth.CodeChallengeMethodParam:  pkceParams.ChallengeMethod,
	})

	return RequestOid4vciCredentialIssuance200JSONResponse{
		RedirectURI: redirectUrl.String(),
	}, nil
}

func (r Wrapper) CallbackOid4vciCredentialIssuance(ctx context.Context, request CallbackOid4vciCredentialIssuanceRequestObject) (CallbackOid4vciCredentialIssuanceResponseObject, error) {
	state := request.Params.State
	oid4vciSession := Oid4vciSession{}
	err := r.openid4vciSessionStore().Get(state, &oid4vciSession)
	if err != nil {
		return nil, core.NotFoundError("Cannot locate active session for state: %s", state)
	}
	if request.Params.Error != nil {
		errorCode := oauth.ErrorCode(*request.Params.Error)
		errorDescription := ""
		if request.Params.ErrorDescription != nil {
			errorDescription = *request.Params.ErrorDescription
		} else {
			errorDescription = fmt.Sprintf("Issuer returned error code: %s", *request.Params.Error)
		}
		return nil, withCallbackURI(oauthError(errorCode, errorDescription), oid4vciSession.remoteRedirectUri())
	}
	code := request.Params.Code
	pkceParams := oid4vciSession.PKCEParams
	issuerDid := oid4vciSession.IssuerDid
	holderDid := oid4vciSession.HolderDid
	tokenEndpoint := oid4vciSession.IssuerTokenEndpoint
	credentialEndpoint := oid4vciSession.IssuerCredentialEndpoint
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("cannot fetch the right endpoints: %s", err.Error())), oid4vciSession.remoteRedirectUri())
	}
	response, err := r.auth.IAMClient().AccessToken(ctx, code, tokenEndpoint, oid4vciSession.RedirectUri, *holderDid, pkceParams.Verifier, false)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.AccessDenied, fmt.Sprintf("error while fetching the access_token from endpoint: %s, error: %s", tokenEndpoint, err.Error())), oid4vciSession.remoteRedirectUri())
	}
	cNonce := response.Get(oauth.CNonceParam)
	proofJWT, err := r.proofJwt(ctx, *holderDid, *issuerDid, &cNonce)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error building proof to fetch the credential from endpoint %s, error: %s", credentialEndpoint, err.Error())), oid4vciSession.remoteRedirectUri())
	}
	credentials, err := r.auth.IAMClient().VerifiableCredentials(ctx, credentialEndpoint, response.AccessToken, proofJWT)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while fetching the credential from endpoint %s, error: %s", credentialEndpoint, err.Error())), oid4vciSession.remoteRedirectUri())
	}
	credential, err := vc.ParseVerifiableCredential(credentials.Credential)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while parsing the credential: %s, error: %s", credentials.Credential, err.Error())), oid4vciSession.remoteRedirectUri())
	}
	err = r.vcr.Verifier().Verify(*credential, true, true, nil)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while verifying the credential from issuer: %s, error: %s", credential.Issuer.String(), err.Error())), oid4vciSession.remoteRedirectUri())
	}
	err = r.vcr.Wallet().Put(ctx, *credential)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while storing credential with id: %s, error: %s", credential.ID, err.Error())), oid4vciSession.remoteRedirectUri())
	}

	log.Logger().Debugf("stored the credential with id: %s, now redirecting to %s", credential.ID, oid4vciSession.RemoteRedirectUri)

	return CallbackOid4vciCredentialIssuance302Response{
		Headers: CallbackOid4vciCredentialIssuance302ResponseHeaders{Location: oid4vciSession.RemoteRedirectUri},
	}, nil
}

func (r *Wrapper) proofJwt(ctx context.Context, holderDid did.DID, audienceDid did.DID, nonce *string) (string, error) {
	// TODO: is this the right key type?
	kid, _, err := r.keyResolver.ResolveKey(holderDid, nil, resolver.NutsSigningKeyType)
	if err != nil {
		return "", fmt.Errorf("failed to resolve key for did (%s): %w", holderDid.String(), err)
	}
	jti, _ := uuid.NewUUID()
	claims := map[string]interface{}{
		"iss": holderDid.String(),
		"aud": audienceDid.String(),
		"jti": jti.String(),
	}
	if nonce != nil {
		claims["nonce"] = nonce
	}
	proofJwt, err := r.jwtSigner.SignJWT(ctx, claims, nil, kid.String())
	if err != nil {
		return "", fmt.Errorf("failed to sign the JWT with kid (%s): %w", kid.String(), err)
	}
	return proofJwt, nil
}

// openid4vciSessionStore is used by the Client to keep track of OpenID4VCI requests
func (r Wrapper) openid4vciSessionStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(oid4vciSessionValidity, "openid4vci")
}
