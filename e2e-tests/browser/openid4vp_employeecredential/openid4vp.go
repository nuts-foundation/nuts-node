//go:build e2e_tests

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

package openid4vp_employeecredential

import (
	"context"
	"fmt"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/e2e-tests/browser/client/iam"
)

type OpenID4VP struct {
	ctx       context.Context
	iamClient iam.ClientInterface
}

func (o OpenID4VP) RequesterUserAccessToken(requesterDID, verifierDID did.DID, user iam.UserDetails, scope string) (*iam.RedirectResponseWithID, error) {
	httpResponse, err := o.iamClient.RequestUserAccessToken(o.ctx, requesterDID.String(), iam.RequestUserAccessTokenJSONRequestBody{
		PreauthorizedUser:   &user,
		RedirectUri:         "https://nodeA", // doesn't really matter where we redirect to
		Scope:               scope,
		AuthorizationServer: "https://nodeA/oauth2/" + verifierDID.String(),
	})
	if err != nil {
		return nil, err
	}
	response, err := iam.ParseRequestUserAccessTokenResponse(httpResponse)
	if err != nil {
		return nil, err
	}
	if response.ApplicationproblemJSONDefault != nil {
		return nil, fmt.Errorf("application problem: %s", response.ApplicationproblemJSONDefault.Detail)
	}
	return response.JSON200, nil
}
func (o OpenID4VP) RetrieveAccessToken(sessionID string) (string, error) {
	httpResponse, err := o.iamClient.RetrieveAccessToken(o.ctx, sessionID)
	if err != nil {
		return "", err
	}
	response, err := iam.ParseRetrieveAccessTokenResponse(httpResponse)
	if err != nil {
		return "", err
	}
	if response.ApplicationproblemJSONDefault != nil {
		return "", fmt.Errorf("application problem: %s", response.ApplicationproblemJSONDefault.Detail)
	}
	return response.JSON200.AccessToken, nil
}

func (o OpenID4VP) IntrospectAccessToken(token string) (*iam.TokenIntrospectionResponse, error) {
	httpResponse, err := o.iamClient.IntrospectAccessTokenWithFormdataBody(o.ctx, iam.IntrospectAccessTokenFormdataRequestBody{
		Token: token,
	})
	if err != nil {
		return nil, err
	}
	response, err := iam.ParseIntrospectAccessTokenResponse(httpResponse)
	if err != nil {
		return nil, err
	}
	return response.JSON200, nil
}
