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

package apps

import (
	"context"
	"fmt"
	"github.com/chromedp/chromedp"
	authAPI "github.com/nuts-foundation/nuts-node/auth/api/auth/v1/client"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/rs/zerolog/log"
)

var NodeClientConfig = core.ClientConfig{Address: "http://localhost:1323"}

type EmployeeInfo struct {
	Identifier string  `json:"identifier"`
	Initials   string  `json:"initials"`
	FamilyName string  `json:"familyName"`
	RoleName   *string `json:"roleName,omitempty"`
}

type SelfSigned struct {
	URL     string
	Context context.Context
}

type SelfSignedSession struct {
	ID                 string
	Contract           string
	EmployeeIdentifier string
	EmployeeName       string
	EmployeeRole       string
}

func (s SelfSigned) Start(organizationDID string, employee EmployeeInfo) (*SelfSignedSession, error) {
	sessionID, webURL, err := s.startSession(organizationDID, employee)
	if err != nil {
		return nil, err
	}
	log.Logger.Info().Msgf("Navigating to %s", webURL)
	result := SelfSignedSession{ID: sessionID}
	err = chromedp.Run(s.Context,
		chromedp.Navigate(webURL),
		chromedp.Text("#contract", &result.Contract),
		chromedp.Text("#employee-identifier", &result.EmployeeIdentifier),
		chromedp.Text("#employee-name", &result.EmployeeName),
		chromedp.Text("#employee-role", &result.EmployeeRole),
	)
	return &result, err
}

func (s SelfSigned) Accept() (string, error) {
	var text string
	err := chromedp.Run(s.Context,
		chromedp.Click("#accept-button"),
		chromedp.Text("//main", &text),
	)
	return text, err
}

func (s SelfSigned) GetSessionStatus(sessionID string) (string, *authAPI.VerifiablePresentation, error) {
	authClient, _ := authAPI.NewClient(NodeClientConfig.Address)
	sessionStatusResponse, err := authClient.GetSignSessionStatus(s.Context, sessionID)
	if err != nil {
		return "", nil, err
	}
	response, err := authAPI.ParseGetSignSessionStatusResponse(sessionStatusResponse)
	if err != nil {
		return "", nil, err
	}
	if response.HTTPResponse.StatusCode != 200 {
		return "", nil, fmt.Errorf("could not get session status: %s", string(response.Body))
	}
	return response.JSON200.Status, response.JSON200.VerifiablePresentation, nil
}

func (s SelfSigned) RequestAccessToken(organizationDID string, purposeOfUse string, presentation *authAPI.VerifiablePresentation) (*authAPI.TokenIntrospectionResponse, error) {
	authClient, _ := authAPI.NewClient(s.URL)
	accessTokenResponse, err := authClient.RequestAccessToken(s.Context, authAPI.RequestAccessTokenJSONRequestBody{
		Authorizer: organizationDID,
		Identity:   presentation,
		Requester:  organizationDID,
		Service:    purposeOfUse,
	})
	if err != nil {
		return nil, err
	}
	response, err := authAPI.ParseRequestAccessTokenResponse(accessTokenResponse)
	if err != nil {
		return nil, err
	}
	introspectionResponse, err := authClient.IntrospectAccessTokenWithFormdataBody(s.Context, authAPI.IntrospectAccessTokenFormdataRequestBody{
		Token: response.JSON200.AccessToken,
	})
	if err != nil {
		return nil, err
	}
	introspectAccessTokenResponse, err := authAPI.ParseIntrospectAccessTokenResponse(introspectionResponse)
	if err != nil {
		return nil, err
	}
	return introspectAccessTokenResponse.JSON200, nil
}

func (s SelfSigned) startSession(organizationDID string, employee EmployeeInfo) (string, string, error) {
	authClient, _ := authAPI.NewClient(NodeClientConfig.Address)
	contractHTTPResponse, err := authClient.DrawUpContract(s.Context, authAPI.DrawUpContractJSONRequestBody{
		Language:    "NL",
		LegalEntity: organizationDID,
		Type:        "BehandelaarLogin",
		Version:     "v3",
	})
	if err != nil {
		return "", "", err
	}
	contractResponse, err := authAPI.ParseDrawUpContractResponse(contractHTTPResponse)
	if err != nil {
		return "", "", err
	}
	if contractResponse.HTTPResponse.StatusCode != 200 {
		return "", "", fmt.Errorf("could not draw up contract: %s", string(contractResponse.Body))
	}

	signSessionHTTPResponse, err := authClient.CreateSignSession(s.Context, authAPI.CreateSignSessionJSONRequestBody{
		Means: "employeeid",
		Params: map[string]interface{}{
			"employer": organizationDID,
			"employee": employee,
		},
		Payload: contractResponse.JSON200.Message,
	})
	if err != nil {
		return "", "", err
	}
	signSessionResponse, err := authAPI.ParseCreateSignSessionResponse(signSessionHTTPResponse)
	if err != nil {
		return "", "", err
	}
	if signSessionResponse.HTTPResponse.StatusCode != 201 {
		return "", "", fmt.Errorf("could not create signing session: %s", string(signSessionResponse.Body))
	}
	return signSessionResponse.JSON201.SessionID, signSessionResponse.JSON201.SessionPtr["url"].(string), nil
}
