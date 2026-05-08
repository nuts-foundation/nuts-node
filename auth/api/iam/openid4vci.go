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
	"github.com/nuts-foundation/nuts-node/auth/openid4vci"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	nutsHttp "github.com/nuts-foundation/nuts-node/http"
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

	// Read and parse the authorization details. Per §5.1.1, type and
	// credential_configuration_id are required for the openid_credential
	// authorization_details flow; the OpenAPI schema enforces both.
	authorizationDetails := []byte("[]")
	var credentialConfigID string
	if len(request.Body.AuthorizationDetails) > 0 {
		authorizationDetails, _ = json.Marshal(request.Body.AuthorizationDetails)
		credentialConfigID = request.Body.AuthorizationDetails[0].CredentialConfigurationId
	}
	// Generate the state and PKCE
	state := crypto.GenerateNonce()
	pkceParams := generatePKCEParams()

	// Figure out our own redirect URL by parsing the did:web and extracting the host.
	redirectUri := clientID.JoinPath(oauth.CallbackPath)
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
		IssuerCredentialIssuer:          credentialIssuerMetadata.CredentialIssuer,
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
		oauth.ClientIDParam:             clientID.String(),
		oauth.ClientIDSchemeParam:       entityClientIDScheme,
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

	// Per §3.3.4 / §8.2: when the Token Response carries authorization_details
	// with credential_identifiers, the Credential Request MUST use a
	// credential_identifier (not credential_configuration_id). When the AS
	// did not return authorization_details, fall back to
	// credential_configuration_id (§3.3.4 scope-flow alternative).
	credentialIdentifier, err := extractCredentialIdentifier(tokenResponse, oauthSession.IssuerCredentialConfigurationID)
	if err != nil {
		return nil, withCallbackURI(oauthError(oauth.ServerError, err.Error()), appCallbackURI)
	}

	// fetch nonce from the Nonce Endpoint (v1.0 Section 7)
	var nonce string
	if oauthSession.IssuerNonceEndpoint != "" {
		nonce, err = r.auth.OpenID4VCIClient().RequestNonce(ctx, oauthSession.IssuerNonceEndpoint)
		if err != nil {
			return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error fetching nonce from %s: %s", oauthSession.IssuerNonceEndpoint, err.Error())), appCallbackURI)
		}
	}

	// build proof and request credential
	credentialResponse, err := r.requestCredentialWithProof(ctx, oauthSession, tokenResponse.AccessToken, credentialIdentifier, nonce)
	if err != nil {
		// Per OpenID4VCI 1.0 §8.3.1.2: on invalid_nonce the wallet retrieves a
		// new c_nonce. Retrying once is local policy to bound recovery; a
		// second invalid_nonce surfaces as a generic ServerError below.
		var oauthErr oauth.OAuth2Error
		if errors.As(err, &oauthErr) && oauthErr.Code == oauth.InvalidNonce && oauthSession.IssuerNonceEndpoint != "" {
			nonce, err = r.auth.OpenID4VCIClient().RequestNonce(ctx, oauthSession.IssuerNonceEndpoint)
			if err != nil {
				return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error fetching nonce for retry from %s: %s", oauthSession.IssuerNonceEndpoint, err.Error())), appCallbackURI)
			}
			credentialResponse, err = r.requestCredentialWithProof(ctx, oauthSession, tokenResponse.AccessToken, credentialIdentifier, nonce)
		}
		if err != nil {
			return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while fetching the credential from endpoint %s, error: %s", oauthSession.IssuerCredentialEndpoint, err.Error())), appCallbackURI)
		}
	}
	if len(credentialResponse.Credentials) == 0 {
		return nil, withCallbackURI(oauthError(oauth.ServerError, "credential response does not contain any credentials"), appCallbackURI)
	}

	// Per OpenID4VCI 1.0 §8.3 the credential field is either a JSON string
	// (JWT-VC, SD-JWT-VC) or a JSON object (JSON-LD). Because Credential is
	// typed as json.RawMessage, the field keeps the raw JSON encoding — for
	// a JWT that includes the surrounding quotes, which ParseVerifiableCredential
	// would reject as invalid base64. Unmarshal the bytes as a Go string first
	// to strip those quotes; on failure (the JSON-LD object case) fall back to
	// the raw bytes as-is.
	rawCredential := credentialResponse.Credentials[0].Credential
	var credentialJSON string
	if err := json.Unmarshal(rawCredential, &credentialJSON); err != nil {
		credentialJSON = string(rawCredential)
	}
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

func (r Wrapper) requestCredentialWithProof(ctx context.Context, oauthSession *OAuthSession, accessToken string, credentialIdentifier string, nonce string) (*openid4vci.CredentialResponse, error) {
	// Per §F.1, the proof JWT `aud` MUST be the Credential Issuer Identifier,
	// not the Authorization Server issuer URL.
	proofJWT, err := r.openid4vciProof(ctx, *oauthSession.OwnDID, oauthSession.IssuerCredentialIssuer, nonce)
	if err != nil {
		return nil, fmt.Errorf("error building proof: %w", err)
	}
	return r.auth.OpenID4VCIClient().RequestCredential(ctx, openid4vci.RequestCredentialOpts{
		CredentialEndpoint:        oauthSession.IssuerCredentialEndpoint,
		AccessToken:               accessToken,
		CredentialConfigurationID: oauthSession.IssuerCredentialConfigurationID,
		CredentialIdentifier:      credentialIdentifier,
		ProofJWT:                  proofJWT,
	})
}

// extractCredentialIdentifier reads authorization_details from the Token
// Response and returns a credential_identifier matching the requested
// configuration. Per OpenID4VCI 1.0 §3.3.4 / §8.2, when the AS returns
// authorization_details with credential_identifiers, the wallet MUST use a
// credential_identifier in the Credential Request — silently falling back
// to credential_configuration_id is not allowed. Returns ("", nil) only
// when the Token Response did not carry authorization_details at all
// (which permits the §3.3.4 scope-flow fallback to credential_configuration_id).
func extractCredentialIdentifier(tokenResponse *oauth.TokenResponse, credentialConfigurationID string) (string, error) {
	raw, ok := tokenResponse.GetAny(oauth.AuthorizationDetailsParam)
	if !ok {
		return "", nil
	}
	bytes, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("token response authorization_details: %w", err)
	}
	var details []struct {
		Type                      string   `json:"type"`
		CredentialConfigurationID string   `json:"credential_configuration_id"`
		CredentialIdentifiers     []string `json:"credential_identifiers"`
	}
	if err := json.Unmarshal(bytes, &details); err != nil {
		return "", fmt.Errorf("token response authorization_details malformed: %w", err)
	}
	for _, d := range details {
		if d.Type != "openid_credential" {
			continue
		}
		if d.CredentialConfigurationID != credentialConfigurationID {
			continue
		}
		if len(d.CredentialIdentifiers) == 0 {
			return "", fmt.Errorf("token response authorization_details for %q is missing credential_identifiers", credentialConfigurationID)
		}
		return d.CredentialIdentifiers[0], nil
	}
	return "", fmt.Errorf("token response authorization_details has no entry for credential_configuration_id %q", credentialConfigurationID)
}

func (r *Wrapper) openid4vciProof(ctx context.Context, holderDid did.DID, audience string, nonce string) (string, error) {
	kid, _, err := r.keyResolver.ResolveKey(holderDid, nil, resolver.AssertionMethod)
	if err != nil {
		return "", fmt.Errorf("failed to resolve key for did (%s): %w", holderDid.String(), err)
	}
	headers := map[string]interface{}{
		"typ": openid4vci.JWTTypeOpenID4VCIProof, // MUST be openid4vci-proof+jwt, which explicitly types the proof JWT as recommended in Section 3.11 of [RFC8725].
		"kid": kid,                               // JOSE Header containing the key ID. If the Credential shall be bound to a DID, the kid refers to a DID URL which identifies a particular key in the DID Document that the Credential shall be bound to.
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
