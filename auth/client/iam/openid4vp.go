/*
 * Nuts node
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
	"github.com/nuts-foundation/nuts-node/http/client"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/piprate/json-gold/ld"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/dpop"
	nutsHttp "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

// ErrPreconditionFailed is returned when a precondition is not met.
var ErrPreconditionFailed = errors.New("precondition failed")

var _ Client = (*OpenID4VPClient)(nil)

type OpenID4VPClient struct {
	httpClient                  HTTPClient
	jwtSigner                   nutsCrypto.JWTSigner
	keyResolver                 resolver.KeyResolver
	strictMode                  bool
	wallet                      holder.Wallet
	ldDocumentLoader            ld.DocumentLoader
	subjectManager              didsubject.Manager
	pdResolver                  PresentationDefinitionResolver
	policyBackend               policy.PDPBackend
	experimentalJwtBearerClient bool
}

// NewClient returns an implementation of Holder
func NewClient(wallet holder.Wallet, keyResolver resolver.KeyResolver, subjectManager didsubject.Manager, jwtSigner nutsCrypto.JWTSigner,
	ldDocumentLoader ld.DocumentLoader, policyBackend policy.PDPBackend, strictMode bool, httpClientTimeout time.Duration,
	experimentalJwtBearerClient bool) *OpenID4VPClient {
	httpClient := HTTPClient{
		strictMode:  strictMode,
		httpClient:  client.NewWithCache(httpClientTimeout),
		keyResolver: keyResolver,
	}
	client := &OpenID4VPClient{
		httpClient:                  httpClient,
		keyResolver:                 keyResolver,
		jwtSigner:                   jwtSigner,
		ldDocumentLoader:            ldDocumentLoader,
		subjectManager:              subjectManager,
		strictMode:                  strictMode,
		wallet:                      wallet,
		policyBackend:               policyBackend,
		experimentalJwtBearerClient: experimentalJwtBearerClient,
	}
	client.pdResolver = PresentationDefinitionResolver{
		pdFetcher:     client,
		policyBackend: policyBackend,
	}
	return client
}

func (c *OpenID4VPClient) ClientMetadata(ctx context.Context, endpoint string) (*oauth.OAuthClientMetadata, error) {
	iamClient := c.httpClient

	metadata, err := iamClient.ClientMetadata(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve OAuth client metadata: %w", err)
	}
	return metadata, nil
}

func (c *OpenID4VPClient) PostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI string, verifierClientState string) (string, error) {
	iamClient := c.httpClient

	responseURL, err := core.ParsePublicURL(verifierResponseURI, c.strictMode)
	if err != nil {
		return "", fmt.Errorf("failed to post error to verifier: %w", err)
	}
	validURL := *responseURL
	if verifierClientState != "" {
		validURL = nutsHttp.AddQueryParams(*responseURL, map[string]string{
			oauth.StateParam: verifierClientState,
		})
	}
	redirectURL, err := iamClient.PostError(ctx, auth2Error, validURL)
	if err != nil {
		return "", fmt.Errorf("failed to post error to verifier: %w", err)
	}

	return redirectURL, nil
}

func (c *OpenID4VPClient) PostAuthorizationResponse(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI string, state string) (string, error) {
	iamClient := c.httpClient

	responseURL, err := core.ParsePublicURL(verifierResponseURI, c.strictMode)
	if err != nil {
		return "", fmt.Errorf("failed to post error to verifier: %w", err)
	}
	redirectURL, err := iamClient.PostAuthorizationResponse(ctx, vp, presentationSubmission, *responseURL, state)
	if err == nil {
		return redirectURL, nil
	}

	return "", fmt.Errorf("failed to post authorization response to verifier: %w", err)
}

func (c *OpenID4VPClient) PresentationDefinition(ctx context.Context, endpoint string) (*pe.PresentationDefinition, error) {
	iamClient := c.httpClient
	parsedURL, err := core.ParsePublicURL(endpoint, c.strictMode)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve presentation definition: %w", err)
	}
	presentationDefinition, err := iamClient.PresentationDefinition(ctx, *parsedURL)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve presentation definition: %w", err)
	}
	return presentationDefinition, nil
}

func (c *OpenID4VPClient) AuthorizationServerMetadata(ctx context.Context, oauthIssuer string) (*oauth.AuthorizationServerMetadata, error) {
	iamClient := c.httpClient
	// the wallet/client acts as authorization server
	metadata, err := iamClient.OAuthAuthorizationServerMetadata(ctx, oauthIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	return metadata, nil
}

func (c *OpenID4VPClient) OpenIDConfiguration(ctx context.Context, issuer string) (*oauth.OpenIDConfiguration, error) {
	iamClient := c.httpClient
	// the wallet/client acts as authorization server
	metadata, err := iamClient.OpenIDConfiguration(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OpenID configuration: %w", err)
	}
	return metadata, nil
}

func (c *OpenID4VPClient) RequestObjectByGet(ctx context.Context, requestURI string) (string, error) {
	iamClient := c.httpClient
	parsedURL, err := core.ParsePublicURL(requestURI, c.strictMode)
	if err != nil {
		return "", fmt.Errorf("invalid request_uri: %w", err)
	}

	requestObject, err := iamClient.RequestObjectByGet(ctx, parsedURL.String())
	if err != nil {
		return "", fmt.Errorf("failed to retrieve JAR Request Object: %w", err)
	}
	return requestObject, nil
}
func (c *OpenID4VPClient) RequestObjectByPost(ctx context.Context, requestURI string, walletMetadata oauth.AuthorizationServerMetadata) (string, error) {
	iamClient := c.httpClient
	parsedURL, err := core.ParsePublicURL(requestURI, c.strictMode)
	if err != nil {
		return "", fmt.Errorf("invalid request_uri: %w", err)
	}

	// TODO: consider adding a 'wallet_nonce'
	metadataBytes, _ := json.Marshal(walletMetadata)
	form := url.Values{oauth.WalletMetadataParam: {string(metadataBytes)}}
	requestObject, err := iamClient.RequestObjectByPost(ctx, parsedURL.String(), form)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve JAR Request Object: %w", err)
	}
	return requestObject, nil
}

func (c *OpenID4VPClient) AccessToken(ctx context.Context, code string, tokenEndpoint string, callbackURI string, subject string, clientID string, codeVerifier string, useDPoP bool) (*oauth.TokenResponse, error) {
	iamClient := c.httpClient
	// validate tokenEndpoint
	parsedURL, err := core.ParsePublicURL(tokenEndpoint, c.strictMode)
	if err != nil {
		return nil, err
	}

	// call token endpoint
	data := url.Values{}
	data.Set(oauth.ClientIDParam, clientID)
	data.Set(oauth.GrantTypeParam, oauth.AuthorizationCodeGrantType)
	data.Set(oauth.CodeParam, code)
	data.Set(oauth.RedirectURIParam, callbackURI)
	data.Set(oauth.CodeVerifierParam, codeVerifier)

	var dpopHeader string
	var dpopKid string
	if useDPoP {
		// create DPoP header
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, parsedURL.String(), nil)
		if err != nil {
			return nil, err
		}
		dids, err := c.subjectManager.ListDIDs(ctx, subject)
		if err != nil {
			return nil, err
		}
		// todo select the right DID based upon metadata
		dpopHeader, dpopKid, err = c.dpop(ctx, dids[0], *request)
		if err != nil {
			return nil, fmt.Errorf("failed to create DPoP header: %w", err)
		}
	}

	token, err := iamClient.AccessToken(ctx, parsedURL.String(), data, dpopHeader)
	if err != nil {
		return nil, fmt.Errorf("remote server: error creating access token: %w", err)
	}
	if dpopKid != "" {
		token.DPoPKid = &dpopKid
	}
	return &token, nil
}

func (c *OpenID4VPClient) RequestRFC021AccessToken(ctx context.Context, clientID string, subjectID string, authServerURL string, scopes string,
	useDPoP bool, additionalCredentials []vc.VerifiableCredential, credentialSelection map[string]string, serviceProviderSubjectID *string) (*oauth.TokenResponse, error) {
	if serviceProviderSubjectID != nil && !c.experimentalJwtBearerClient {
		return nil, errors.New("jwt-bearer two-VP flow requires auth.experimental.jwt_bearer_client = true")
	}
	iamClient := c.httpClient
	metadata, err := c.AuthorizationServerMetadata(ctx, authServerURL)
	if err != nil {
		return nil, err
	}
	if serviceProviderSubjectID != nil && !slices.Contains(metadata.GrantTypesSupported, oauth.JwtBearerGrantType) {
		return nil, errors.New("authorization server does not advertise jwt-bearer support")
	}
	if serviceProviderSubjectID != nil {
		return c.requestJwtBearerAccessToken(ctx, clientID, subjectID, *serviceProviderSubjectID, authServerURL, scopes, additionalCredentials, credentialSelection, metadata)
	}

	// Resolve the presentation definition: from remote AS when available, local policy otherwise
	resolved, err := c.pdResolver.Resolve(ctx, scopes, *metadata)
	if err != nil {
		return nil, err
	}
	presentationDefinition := &resolved.PresentationDefinition

	params := holder.BuildParams{
		Audience:   authServerURL,
		DIDMethods: metadata.DIDMethodsSupported,
		Expires:    time.Now().Add(time.Second * 5),
		Format:     metadata.VPFormatsSupported,
		Nonce:      nutsCrypto.GenerateNonce(),
	}

	subjectDIDs, err := c.subjectManager.ListDIDs(ctx, subjectID)
	if err != nil {
		return nil, err
	}

	subjectDIDs, err = filterDIDsByMethods(subjectDIDs, metadata.DIDMethodsSupported)
	if err != nil {
		return nil, err
	}

	// each additional credential can be used by each DID
	additionalWalletCredentials := map[did.DID][]vc.VerifiableCredential{}
	for _, subjectDID := range subjectDIDs {
		for _, curr := range additionalCredentials {
			additionalWalletCredentials[subjectDID] = append(additionalWalletCredentials[subjectDID], credential.AutoCorrectSelfAttestedCredential(curr, subjectDID))
		}
	}
	vp, submission, err := c.wallet.BuildSubmission(ctx, subjectDIDs, additionalWalletCredentials, *presentationDefinition, credentialSelection, params)
	if err != nil {
		return nil, err
	}
	subjectDID, err := did.ParseDID(vp.Holder.String())
	if err != nil {
		return nil, err
	}

	assertion := vp.Raw()
	presentationSubmission, _ := json.Marshal(submission)
	data := url.Values{}
	data.Set(oauth.ClientIDParam, clientID)
	data.Set(oauth.GrantTypeParam, oauth.VpTokenGrantType)
	data.Set(oauth.AssertionParam, assertion)
	data.Set(oauth.PresentationSubmissionParam, string(presentationSubmission))
	data.Set(oauth.ScopeParam, resolved.Scope)

	// create DPoP header
	var dpopHeader string
	var dpopKid string
	if useDPoP {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, metadata.TokenEndpoint, nil)
		if err != nil {
			return nil, err
		}
		dpopHeader, dpopKid, err = c.dpop(ctx, *subjectDID, *request)
		if err != nil {
			return nil, fmt.Errorf("failed to create DPoP header: %w", err)
		}
	}

	log.Logger().Tracef("Requesting access token from '%s' for scope '%s'\n  VP: %s\n  Submission: %s", metadata.TokenEndpoint, scopes, assertion, string(presentationSubmission))
	token, err := iamClient.AccessToken(ctx, metadata.TokenEndpoint, data, dpopHeader)
	if err != nil {
		// the error could be a http error, we just relay it here to make use of any 400 status codes.
		return nil, err
	}
	tokenResponse := oauth.TokenResponse{
		AccessToken: token.AccessToken,
		ExpiresIn:   token.ExpiresIn,
		TokenType:   token.TokenType,
		Scope:       &scopes,
	}
	if dpopKid != "" {
		tokenResponse.DPoPKid = &dpopKid
	}
	return &tokenResponse, nil
}

// requestJwtBearerAccessToken implements the RFC 7523 jwt-bearer two-VP token request flow.
// It builds VP1 from the HCP wallet (using the organization PD) and VP2 from the SP wallet (using the
// service_provider PD), assembles them as `assertion` and `client_assertion`, and POSTs the token request.
func (c *OpenID4VPClient) requestJwtBearerAccessToken(ctx context.Context, clientID string, subjectID string, serviceProviderSubjectID string,
	authServerURL string, scopes string, additionalCredentials []vc.VerifiableCredential, credentialSelection map[string]string,
	metadata *oauth.AuthorizationServerMetadata) (*oauth.TokenResponse, error) {
	match, err := c.policyBackend.FindCredentialProfile(ctx, scopes)
	if err != nil {
		return nil, fmt.Errorf("local PD resolution failed: %w", err)
	}
	orgPD, hasOrg := match.WalletOwnerMapping[pe.WalletOwnerOrganization]
	if !hasOrg {
		return nil, fmt.Errorf("no organization presentation definition for scope %q", match.CredentialProfileScope)
	}
	spPD, hasSP := match.WalletOwnerMapping[pe.WalletOwnerServiceProvider]
	if !hasSP {
		return nil, fmt.Errorf("no service_provider presentation definition for scope %q", match.CredentialProfileScope)
	}
	params := holder.BuildParams{
		Audience:   authServerURL,
		DIDMethods: metadata.DIDMethodsSupported,
		Expires:    time.Now().Add(time.Second * 5),
		Format:     metadata.VPFormatsSupported,
		Nonce:      nutsCrypto.GenerateNonce(),
	}
	vp1, err := c.buildSubmissionForSubject(ctx, subjectID, orgPD, additionalCredentials, credentialSelection, params, metadata.DIDMethodsSupported)
	if err != nil {
		return nil, err
	}
	vp2, err := c.buildSubmissionForSubject(ctx, serviceProviderSubjectID, spPD, additionalCredentials, credentialSelection, params, metadata.DIDMethodsSupported)
	if err != nil {
		return nil, err
	}
	data := url.Values{}
	data.Set(oauth.ClientIDParam, clientID)
	data.Set(oauth.GrantTypeParam, oauth.JwtBearerGrantType)
	data.Set(oauth.AssertionParam, vp1.Raw())
	data.Set(oauth.ClientAssertionTypeParam, oauth.JwtBearerClientAssertionType)
	data.Set(oauth.ClientAssertionParam, vp2.Raw())
	data.Set(oauth.ScopeParam, scopes)

	log.Logger().Tracef("Requesting jwt-bearer access token from '%s' for scope '%s'\n  VP1: %s\n  VP2: %s", metadata.TokenEndpoint, scopes, vp1.Raw(), vp2.Raw())
	token, err := c.httpClient.AccessToken(ctx, metadata.TokenEndpoint, data, "")
	if err != nil {
		return nil, err
	}
	return &oauth.TokenResponse{
		AccessToken: token.AccessToken,
		ExpiresIn:   token.ExpiresIn,
		TokenType:   token.TokenType,
		Scope:       &scopes,
	}, nil
}

// buildSubmissionForSubject lists DIDs for the given subject, filters them to those whose method is supported
// by the AS, and asks the wallet to build a VP that fulfills the given PresentationDefinition.
func (c *OpenID4VPClient) buildSubmissionForSubject(ctx context.Context, subjectID string, presentationDefinition pe.PresentationDefinition,
	additionalCredentials []vc.VerifiableCredential, credentialSelection map[string]string, params holder.BuildParams,
	supportedDIDMethods []string) (*vc.VerifiablePresentation, error) {
	subjectDIDs, err := c.subjectManager.ListDIDs(ctx, subjectID)
	if err != nil {
		return nil, err
	}
	subjectDIDs, err = filterDIDsByMethods(subjectDIDs, supportedDIDMethods)
	if err != nil {
		return nil, err
	}
	additionalWalletCredentials := map[did.DID][]vc.VerifiableCredential{}
	for _, subjectDID := range subjectDIDs {
		for _, curr := range additionalCredentials {
			additionalWalletCredentials[subjectDID] = append(additionalWalletCredentials[subjectDID], credential.AutoCorrectSelfAttestedCredential(curr, subjectDID))
		}
	}
	vp, _, err := c.wallet.BuildSubmission(ctx, subjectDIDs, additionalWalletCredentials, presentationDefinition, credentialSelection, params)
	if err != nil {
		return nil, err
	}
	return vp, nil
}

// filterDIDsByMethods drops DIDs whose method is not in supportedMethods. Returns ErrPreconditionFailed when
// none of the subject's DIDs use a supported method.
func filterDIDsByMethods(subjectDIDs []did.DID, supportedMethods []string) ([]did.DID, error) {
	j := 0
	allMethods := map[string]struct{}{}
	for i, d := range subjectDIDs {
		allMethods[d.Method] = struct{}{}
		if slices.Contains(supportedMethods, d.Method) {
			subjectDIDs[j] = subjectDIDs[i]
			j++
		}
	}
	subjectDIDs = subjectDIDs[:j]
	if len(subjectDIDs) == 0 {
		availableMethods := make([]string, 0, len(allMethods))
		for key := range maps.Keys(allMethods) {
			availableMethods = append(availableMethods, key)
		}
		return nil, errors.Join(ErrPreconditionFailed, fmt.Errorf("did method mismatch, requested: %v, available: %v", supportedMethods, availableMethods))
	}
	return subjectDIDs, nil
}

func (c *OpenID4VPClient) OpenIdCredentialIssuerMetadata(ctx context.Context, oauthIssuerURI string) (*oauth.OpenIDCredentialIssuerMetadata, error) {
	iamClient := c.httpClient
	rsp, err := iamClient.OpenIdCredentialIssuerMetadata(ctx, oauthIssuerURI)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Openid credential issuer metadata: %w", err)
	}
	return rsp, nil
}

func (c *OpenID4VPClient) VerifiableCredentials(ctx context.Context, credentialEndpoint string, accessToken string, proofJWT string) (*CredentialResponse, error) {
	iamClient := c.httpClient
	rsp, err := iamClient.VerifiableCredentials(ctx, credentialEndpoint, accessToken, proofJWT)
	if err != nil {
		return nil, fmt.Errorf("remote server: failed to retrieve credentials: %w", err)
	}
	return rsp, nil
}

func (c *OpenID4VPClient) dpop(ctx context.Context, requester did.DID, request http.Request) (string, string, error) {
	// find the key to sign the DPoP token with
	keyID, _, err := c.keyResolver.ResolveKey(requester, nil, resolver.AssertionMethod)
	if err != nil {
		return "", "", err
	}

	token := dpop.New(request)
	jwt, err := c.jwtSigner.SignDPoP(ctx, *token, keyID)
	if err != nil {
		return "", "", err
	}
	return jwt, keyID, nil
}
