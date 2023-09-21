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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/auth/api/auth/v1/client"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// serviceToService adds support for service-to-service OAuth2 flows,
// which uses a custom vp_token grant to authenticate calls to the token endpoint.
// Clients first call the presentation definition endpoint to get a presentation definition for the desired scope,
// then create a presentation submission given the definition which is posted to the token endpoint as vp_token.
// The AS then returns an access token with the requested scope.
// Requires:
// - GET /presentation_definition?scope=... (returns a presentation definition)
// - POST /token (with vp_token grant)
type serviceToService struct {
}

func (s serviceToService) Routes(router core.EchoRouter) {
	router.Add("GET", "/public/oauth2/:did/presentation_definition", func(echoCtx echo.Context) error {
		// TODO: Read scope, map to presentation definition, return
		return echoCtx.JSON(http.StatusOK, map[string]string{})
	})
}

func (s serviceToService) validateVPToken(params map[string]string) (string, error) {
	submission := params["presentation_submission"]
	scope := params["scope"]
	vp_token := params["vp_token"]
	if submission == "" || scope == "" || vp_token == "" {
		// TODO: right error response
		return "", errors.New("missing required parameters")
	}
	// TODO: https://github.com/nuts-foundation/nuts-node/issues/2418
	// TODO: verify parameters
	return scope, nil
}

func (s serviceToService) handleAuthzRequest(_ map[string]string, _ *Session) (*authzResponse, error) {
	// Protocol does not support authorization code flow
	return nil, nil
}

func (r Wrapper) RequestAccessToken(ctx context.Context, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error) {
	if request.Body == nil {
		// why did oapi-codegen generate a pointer for the body??
		return nil, core.InvalidInputError("missing request body")
	}
	// resolve wallet
	requestHolder, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.NotFoundError("did not found: %w", err)
	}
	isWallet, err := r.vdr.IsOwner(ctx, *requestHolder)
	if err != nil {
		return nil, err
	}
	if !isWallet {
		return nil, core.InvalidInputError("did not owned by this node: %w", err)
	}

	// resolve verifier metadata
	requestVerifier, err := did.ParseDID(request.Body.Verifier)
	if err != nil {
		return nil, core.InvalidInputError("invalid verifier: %w", err)
	}
	_, _, err = r.vdr.Resolver().Resolve(*requestVerifier, nil)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			return nil, core.InvalidInputError("verifier not found: %w", err)
		}
		return nil, err
	}
	client := NewHTTPClient(core.ClientConfig{}) // todo: how to get this config?
	metadata, err := client.OAuthAuthorizationServerMetadata(ctx, *requestVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}

	// get the presentation definition from the verifier
	scopes := strings.Split(request.Body.Scope, " ") // form encoded, so space delimited
	presentationDefinitions, err := client.PresentationDefinition(ctx, metadata.PresentationDefinitionEndpoint, scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve presentation definitions: %w", err)
	}

	walletCredentials, err := r.vcr.Wallet().List(ctx, *requestHolder)
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
		expires := time.Now().Add(time.Minute * 15) //todo
		nonce := generateNonce()
		vp, err := r.vcr.Wallet().BuildPresentation(ctx, credentials, holder.PresentationOptions{ProofOptions: proof.ProofOptions{
			Created:   time.Now(),
			Challenge: &nonce,
			Expires:   &expires,
		}}, requestHolder, true)
		if err != nil {
			return nil, fmt.Errorf("failed to create verifiable presentation: %w", err)
		}
		token, err := client.AccessToken(ctx, metadata.TokenEndpoint, *vp, submission, scopes)
		if err != nil {
			if isInvalidGrantError(err) {
				log.Logger().Debugf("token endpoint returned invalid_grant, trying next presentation definition: %w", err)
				continue
			}
			return nil, fmt.Errorf("failed to request access token: %w", err)
		}
		return RequestAccessToken200JSONResponse(token), nil
	}

	return nil, core.Error(http.StatusPreconditionFailed, "no matching credentials")
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
	var response client.AccessTokenRequestFailedResponse // todo, to be generated
	if errors.As(err, target) {
		_ = json.Unmarshal(target.ResponseBody, &response)
		if response.Error == "invalid_grant" {
			return true
		}
	}
	return false
}
