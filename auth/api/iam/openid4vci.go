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
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

var timeFunc = time.Now

func (r Wrapper) RequestOpenid4VCICredentialIssuance(ctx context.Context, request RequestOpenid4VCICredentialIssuanceRequestObject) (RequestOpenid4VCICredentialIssuanceResponseObject, error) {
	if request.Body == nil {
		// why did oapi-codegen generate a pointer for the body??
		return nil, core.InvalidInputError("missing request body")
	}
	walletDID, err := did.ParseDID(request.Body.WalletDid)
	if err != nil {
		return nil, core.InvalidInputError("invalid wallet DID")
	}
	if owned, err := r.subjectOwns(ctx, request.SubjectID, *walletDID); err != nil {
		return nil, err
	} else if !owned {
		return nil, core.InvalidInputError("wallet DID does not belong to the subject")
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

	clientID := r.subjectToBaseURL(request.SubjectID)

	// Validate and process authorization details
	authorizationDetails := []byte("[]")
	var credentialConfigID string
	if len(request.Body.AuthorizationDetails) > 0 {
		var sanitized []map[string]interface{}
		credentialConfigID, sanitized, err = validateAuthorizationDetails(request.Body.AuthorizationDetails, credentialIssuerMetadata)
		if err != nil {
			return nil, core.InvalidInputError("%s", err)
		}
		authorizationDetails, err = json.Marshal(sanitized)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal authorization_details: %w", err)
		}
	}
	// Generate the state and PKCE
	state := crypto.GenerateNonce()
	pkceParams := generatePKCEParams()

	// Figure out our own redirect URL by parsing the did:web and extracting the host.
	redirectUri := clientID.JoinPath(oauth.CallbackPath)
	// Extract proof_signing_alg_values_supported from the credential configuration (v1.0 Appendix F.1)
	var proofSigningAlgValues []string
	if credentialConfigID != "" {
		if config, exists := credentialIssuerMetadata.CredentialConfigurationsSupported[credentialConfigID]; exists {
			proofSigningAlgValues, err = openid4vci.ProofSigningAlgValues(config)
			if err != nil {
				return nil, core.Error(http.StatusFailedDependency, "%s", err)
			}
		}
	}
	// Store the session
	err = r.oauthClientStateStore().Put(state, &OAuthSession{
		AuthorizationServerMetadata: authzServerMetadata,
		ClientFlow:                  credentialRequestClientFlow,
		OwnSubject:                  &request.SubjectID,
		OwnDID:                      walletDID,
		RedirectURI:                 request.Body.RedirectUri,
		PKCEParams:                  pkceParams,
		// OpenID4VCI issuers may use multiple Authorization Servers
		// We must use the token_endpoint that corresponds to the same Authorization Server used for the authorization_endpoint
		TokenEndpoint:                   authzServerMetadata.TokenEndpoint,
		IssuerURL:                       authzServerMetadata.Issuer,
		IssuerCredentialEndpoint:        credentialIssuerMetadata.CredentialEndpoint,
		IssuerNonceEndpoint:             credentialIssuerMetadata.NonceEndpoint,
		IssuerCredentialConfigurationID: credentialConfigID,
		ProofSigningAlgValuesSupported:  proofSigningAlgValues,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}
	// Build the redirect URL, the client browser should be redirected to.
	authorizationEndpoint, err := url.Parse(authzServerMetadata.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the authorization_endpoint: %w", err)
	}
	authzParams := url.Values{
		oauth.ResponseTypeParam:         {oauth.CodeResponseType},
		oauth.StateParam:                {state},
		oauth.ClientIDParam:             {clientID.String()},
		oauth.ClientIDSchemeParam:       {entityClientIDScheme},
		oauth.AuthorizationDetailsParam: {string(authorizationDetails)},
		oauth.RedirectURIParam:          {redirectUri.String()},
		oauth.CodeChallengeParam:        {pkceParams.Challenge},
		oauth.CodeChallengeMethodParam:  {pkceParams.ChallengeMethod},
	}

	var redirectUrl url.URL
	if authzServerMetadata.PushedAuthorizationRequestEndpoint != "" {
		parResponse, parErr := r.auth.IAMClient().PushedAuthorizationRequest(ctx, authzServerMetadata.PushedAuthorizationRequestEndpoint, authzParams)
		if parErr != nil {
			return nil, fmt.Errorf("PAR request failed: %w", parErr)
		}
		redirectUrl = nutsHttp.AddQueryParams(*authorizationEndpoint, map[string]string{
			oauth.ClientIDParam: clientID.String(),
			"request_uri":       parResponse.RequestURI,
		})
	} else {
		params := make(map[string]string, len(authzParams))
		for k, v := range authzParams {
			params[k] = v[0]
		}
		redirectUrl = nutsHttp.AddQueryParams(*authorizationEndpoint, params)
	}

	return RequestOpenid4VCICredentialIssuance200JSONResponse{
		RedirectURI: redirectUrl.String(),
	}, nil
}

func (r Wrapper) handleOpenID4VCICallback(ctx context.Context, authorizationCode string, oauthSession *OAuthSession) (CallbackResponseObject, error) {
	appCallbackURI := oauthSession.redirectURI()

	baseURL := r.subjectToBaseURL(*oauthSession.OwnSubject)
	clientID := baseURL.String()
	checkURL := baseURL.JoinPath(oauth.CallbackPath)

	if oauthSession.OwnDID == nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, "missing wallet DID in session"), appCallbackURI)
	}

	// use code to request access token from remote token endpoint
	tokenResponse, err := r.auth.IAMClient().AccessToken(ctx, authorizationCode, oauthSession.TokenEndpoint, checkURL.String(), *oauthSession.OwnSubject, clientID, oauthSession.PKCEParams.Verifier, false)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.AccessDenied, fmt.Sprintf("error while fetching the access_token from endpoint: %s, error: %s", oauthSession.TokenEndpoint, err.Error())), appCallbackURI)
	}

	// fetch nonce from the Nonce Endpoint (v1.0 Section 7)
	var nonce string
	if oauthSession.IssuerNonceEndpoint != "" {
		nonce, err = r.auth.IAMClient().RequestNonce(ctx, oauthSession.IssuerNonceEndpoint)
		if err != nil {
			return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error fetching nonce from %s: %s", oauthSession.IssuerNonceEndpoint, err.Error())), appCallbackURI)
		}
	}

	// build proof and request credential
	credentialResponse, err := r.requestCredentialWithProof(ctx, oauthSession, tokenResponse.AccessToken, nonce)
	if err != nil {
		// on invalid_nonce: fetch a fresh nonce and retry once
		var oidcErr openid4vci.Error
		if errors.As(err, &oidcErr) && oidcErr.Code == openid4vci.InvalidNonce && oauthSession.IssuerNonceEndpoint != "" {
			nonce, err = r.auth.IAMClient().RequestNonce(ctx, oauthSession.IssuerNonceEndpoint)
			if err != nil {
				return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error fetching nonce for retry from %s: %s", oauthSession.IssuerNonceEndpoint, err.Error())), appCallbackURI)
			}
			credentialResponse, err = r.requestCredentialWithProof(ctx, oauthSession, tokenResponse.AccessToken, nonce)
		}
		if err != nil {
			return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while fetching the credential from endpoint %s, error: %s", oauthSession.IssuerCredentialEndpoint, err.Error())), appCallbackURI)
		}
	}
	if credentialResponse.TransactionID != "" {
		return nil, withCallbackURI(oauthError(oauth.ServerError, "deferred credential issuance is not supported"), appCallbackURI)
	}
	if len(credentialResponse.Credentials) == 0 {
		return nil, withCallbackURI(oauthError(oauth.ServerError, "credential response does not contain any credentials"), appCallbackURI)
	}

	credentialJSON := string(credentialResponse.Credentials[0].Credential)
	credential, err := vc.ParseVerifiableCredential(credentialJSON)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while parsing the credential: %s, error: %s", credentialJSON, err.Error())), appCallbackURI)
	}
	err = r.vcr.Verifier().Verify(*credential, true, true, nil)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while verifying the credential from issuer: %s, error: %s", credential.Issuer.String(), err.Error())), appCallbackURI)
	}
	err = r.vcr.Wallet().Put(ctx, *credential)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while storing credential with id: %s, error: %s", credential.ID, err.Error())), appCallbackURI)
	}
	return Callback302Response{
		Headers: Callback302ResponseHeaders{Location: appCallbackURI.String()},
	}, nil
}

func (r Wrapper) requestCredentialWithProof(ctx context.Context, oauthSession *OAuthSession, accessToken string, nonce string) (*openid4vci.CredentialResponse, error) {
	proofJWT, err := r.openid4vciProof(ctx, oauthSession, nonce)
	if err != nil {
		return nil, fmt.Errorf("error building proof: %w", err)
	}
	return r.auth.IAMClient().VerifiableCredentials(ctx, oauthSession.IssuerCredentialEndpoint, accessToken, oauthSession.IssuerCredentialConfigurationID, proofJWT)
}

func (r *Wrapper) openid4vciProof(ctx context.Context, session *OAuthSession, nonce string) (string, error) {
	if session.OwnDID == nil {
		return "", errors.New("session has no holder DID")
	}
	holderDid := *session.OwnDID
	kid, pubKey, err := r.keyResolver.ResolveKey(holderDid, nil, resolver.AssertionMethod)
	if err != nil {
		return "", fmt.Errorf("failed to resolve key for did (%s): %w", holderDid.String(), err)
	}
	if len(session.ProofSigningAlgValuesSupported) > 0 {
		alg, algErr := crypto.SignatureAlgorithm(pubKey)
		if algErr != nil {
			return "", fmt.Errorf("failed to determine signing algorithm: %w", algErr)
		}
		if err = openid4vci.ValidateProofSigningAlg(alg.String(), session.ProofSigningAlgValuesSupported); err != nil {
			return "", err
		}
	}
	headers := map[string]interface{}{
		"typ": openid4vci.JWTTypeOpenID4VCIProof, // MUST be openid4vci-proof+jwt, which explicitly types the proof JWT as recommended in Section 3.11 of [RFC8725].
		"kid": kid,                               // JOSE Header containing the key ID. If the Credential shall be bound to a DID, the kid refers to a DID URL which identifies a particular key in the DID Document that the Credential shall be bound to.
	}
	claims := map[string]interface{}{
		jwt.IssuerKey:   holderDid.String(),
		jwt.AudienceKey: session.IssuerURL, // Credential Issuer Identifier
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

// validateAuthorizationDetails validates the authorization_details entries per v1.0 Section 5.1.1.
// It returns the credential_configuration_id and sanitized entries (only known keys, with locations injected).
// Only a single entry is supported; multiple entries are rejected.
func validateAuthorizationDetails(details []map[string]interface{}, metadata *oauth.OpenIDCredentialIssuerMetadata) (string, []map[string]interface{}, error) {
	if len(details) != 1 {
		return "", nil, errors.New("invalid authorization_details: exactly one entry is supported")
	}
	if len(metadata.CredentialConfigurationsSupported) == 0 {
		return "", nil, errors.New("invalid authorization_details: issuer does not advertise any credential configurations")
	}
	entry := details[0]
	typ, _ := entry["type"].(string)
	if typ != "openid_credential" {
		return "", nil, errors.New("invalid authorization_details: type must be \"openid_credential\"")
	}
	configID, ok := entry["credential_configuration_id"].(string)
	if !ok || configID == "" {
		return "", nil, errors.New("invalid authorization_details: credential_configuration_id is required")
	}
	if _, exists := metadata.CredentialConfigurationsSupported[configID]; !exists {
		return "", nil, fmt.Errorf("invalid authorization_details: credential_configuration_id %q not found in issuer metadata", configID)
	}
	// Build sanitized entry with only known fields
	sanitized := map[string]interface{}{
		"type":                        typ,
		"credential_configuration_id": configID,
	}
	// Inject locations when authorization_servers is present (v1.0 Section 5.1.1)
	if len(metadata.AuthorizationServers) > 0 {
		sanitized["locations"] = []string{metadata.CredentialIssuer}
	}
	return configID, []map[string]interface{}{sanitized}, nil
}
