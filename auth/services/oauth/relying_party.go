/*
* Nuts node
* Copyright (C) 2021 Nuts community
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
 */

package oauth

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/api/auth/v1/client"
	"github.com/nuts-foundation/nuts-node/auth/client/iam"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

var _ RelyingParty = (*relyingParty)(nil)

type relyingParty struct {
	keyResolver       types.KeyResolver
	privateKeyStore   nutsCrypto.KeyStore
	serviceResolver   didman.CompoundServiceResolver
	strictMode        bool
	httpClientTimeout time.Duration
	httpClientTLS     *tls.Config
	wallet            holder.Wallet
}

// NewRelyingParty returns an implementation of OAuthRelyingParty
func NewRelyingParty(
	didResolver types.DIDResolver, serviceResolver didman.CompoundServiceResolver, privateKeyStore nutsCrypto.KeyStore,
	wallet holder.Wallet, httpClientTimeout time.Duration, httpClientTLS *tls.Config, strictMode bool) RelyingParty {
	return &relyingParty{
		keyResolver:       didservice.KeyResolver{Resolver: didResolver},
		serviceResolver:   serviceResolver,
		privateKeyStore:   privateKeyStore,
		httpClientTimeout: httpClientTimeout,
		httpClientTLS:     httpClientTLS,
		strictMode:        strictMode,
		wallet:            wallet,
	}
}

// CreateJwtGrant creates a JWT Grant from the given CreateJwtGrantRequest
func (s *relyingParty) CreateJwtGrant(ctx context.Context, request services.CreateJwtGrantRequest) (*services.JwtBearerTokenResult, error) {
	requester, err := did.ParseDID(request.Requester)
	if err != nil {
		return nil, err
	}

	// todo add checks for missing values?
	authorizer, err := did.ParseDID(request.Authorizer)
	if err != nil {
		return nil, err
	}

	for _, verifiableCredential := range request.Credentials {
		validator := credential.FindValidator(verifiableCredential)
		if err := validator.Validate(verifiableCredential); err != nil {
			return nil, fmt.Errorf("invalid VerifiableCredential: %w", err)
		}
	}

	endpointURL, err := s.serviceResolver.GetCompoundServiceEndpoint(*authorizer, request.Service, services.OAuthEndpointType, true)
	if err != nil {
		return nil, fmt.Errorf("could not fetch authorizer's 'oauth' endpoint from compound service: %w", err)
	}

	keyVals := claimsFromRequest(request, endpointURL)

	signingKeyID, _, err := s.keyResolver.ResolveKey(*requester, nil, types.NutsSigningKeyType)
	if err != nil {
		return nil, err
	}
	signingString, err := s.privateKeyStore.SignJWT(ctx, keyVals, nil, signingKeyID.String())
	if err != nil {
		return nil, err
	}

	return &services.JwtBearerTokenResult{BearerToken: signingString, AuthorizationServerEndpoint: endpointURL}, nil
}

func (s *relyingParty) RequestRFC003AccessToken(ctx context.Context, jwtGrantToken string, authorizationServerEndpoint url.URL) (*oauth.TokenResponse, error) {
	if s.strictMode && strings.ToLower(authorizationServerEndpoint.Scheme) != "https" {
		return nil, fmt.Errorf("authorization server endpoint must be HTTPS when in strict mode: %s", authorizationServerEndpoint.String())
	}
	httpClient := &http.Client{}
	if s.httpClientTLS != nil {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: s.httpClientTLS,
		}
	}
	authClient, err := client.NewHTTPClient("", s.httpClientTimeout, client.WithHTTPClient(httpClient), client.WithRequestEditorFn(core.UserAgentRequestEditor))
	if err != nil {
		return nil, fmt.Errorf("unable to create HTTP client: %w", err)
	}
	accessTokenResponse, err := authClient.CreateAccessToken(ctx, authorizationServerEndpoint, jwtGrantToken)
	if err != nil {
		return nil, fmt.Errorf("remote server/nuts node returned error creating access token: %w", err)
	}
	return accessTokenResponse, nil
}

func (s *relyingParty) RequestRFC021AccessToken(ctx context.Context, requestHolder did.DID, verifier did.DID, scopes []string) (*oauth.TokenResponse, error) {
	iamClient := iam.NewHTTPClient(s.strictMode, s.httpClientTimeout, s.httpClientTLS)
	metadata, err := iamClient.OAuthAuthorizationServerMetadata(ctx, verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}

	// get the presentation definition from the verifier
	presentationDefinitions, err := iamClient.PresentationDefinition(ctx, metadata.PresentationDefinitionEndpoint, scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve presentation definitions: %w", err)
	}

	walletCredentials, err := s.wallet.List(ctx, requestHolder)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve wallet credentials: %w", err)
	}

	// for each presentation definition, match against the wallet's credentials
	// if there's a match, create a VP and call the token endpoint
	// If the token endpoint fails with an invalid_grant error, try the next presentation definition
	// If the token endpoint fails with any other error, return the error
	// If the token endpoint succeeds, return the access token
	// If no presentation definition matches, return a 400 "no matching credentials" error
	for _, presentationDefinition := range presentationDefinitions {
		submission, credentials, err := presentationDefinition.Match(walletCredentials)
		if err != nil {
			return nil, fmt.Errorf("failed to match presentation definition: %w", err)
		}
		if len(credentials) == 0 {
			continue
		}
		expires := time.Now().Add(time.Minute * 15) // TODO
		nonce := generateNonce()
		vp, err := s.wallet.BuildPresentation(ctx, credentials, holder.PresentationOptions{ProofOptions: proof.ProofOptions{
			Created:   time.Now(),
			Challenge: &nonce,
			Expires:   &expires,
		}}, &requestHolder, true)
		if err != nil {
			return nil, fmt.Errorf("failed to create verifiable presentation: %w", err)
		}
		token, err := iamClient.AccessToken(ctx, metadata.TokenEndpoint, *vp, submission, scopes)
		if err != nil {
			if isInvalidGrantError(err) {
				log.Logger().Debugf("token endpoint returned invalid_grant, trying next presentation definition: %s", err.Error())
				continue
			}
			return nil, fmt.Errorf("failed to request access token: %w", err)
		}
		return &oauth.TokenResponse{
			AccessToken: token.AccessToken,
			ExpiresIn:   token.ExpiresIn,
			TokenType:   token.TokenType,
		}, nil
	}

	return nil, core.Error(http.StatusPreconditionFailed, "no matching credentials")
}

var timeFunc = time.Now

// standalone func for easier testing
func claimsFromRequest(request services.CreateJwtGrantRequest, audience string) map[string]interface{} {
	result := map[string]interface{}{}
	result[jwt.AudienceKey] = audience
	result[jwt.ExpirationKey] = timeFunc().Add(BearerTokenMaxValidity * time.Second).Unix()
	result[jwt.IssuedAtKey] = timeFunc().Unix()
	result[jwt.IssuerKey] = request.Requester
	result[jwt.NotBeforeKey] = 0
	result[jwt.SubjectKey] = request.Authorizer
	result[purposeOfUseClaimDeprecated] = request.Service
	result[purposeOfUseClaim] = request.Service
	if request.IdentityVP != nil {
		result[userIdentityClaim] = *request.IdentityVP
	}
	result[vcClaim] = request.Credentials

	return result
}

func generateNonce() string {
	buf := make([]byte, 128/8)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(buf)
}

func isInvalidGrantError(err error) bool {
	var target *core.HttpError
	var response oauth.ErrorResponse
	if errors.As(err, target) {
		_ = json.Unmarshal(target.ResponseBody, &response)
		if response.Error == "invalid_grant" {
			return true
		}
	}
	return false
}
