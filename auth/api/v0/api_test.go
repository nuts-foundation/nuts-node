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

package v0

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/mock"
)




type TestContext struct {
	ctrl         *gomock.Controller
	echoMock     *mock.MockContext
	authMock     *auth.MockAuthenticationServices
	oauthMock    *services.MockOAuthClient
	notaryMock   *services.MockContractNotary
	contractMock *services.MockContractClient
	wrapper      Wrapper
}

var createContext = func(t *testing.T) *TestContext {
	ctrl := gomock.NewController(t)
	authMock := auth.NewMockAuthenticationServices(ctrl)
	oauthMock := services.NewMockOAuthClient(ctrl)
	notaryMock := services.NewMockContractNotary(ctrl)
	contractMock := services.NewMockContractClient(ctrl)

	authMock.EXPECT().OAuthClient().AnyTimes().Return(oauthMock)
	authMock.EXPECT().ContractClient().AnyTimes().Return(contractMock)
	authMock.EXPECT().ContractNotary().AnyTimes().Return(notaryMock)

	return &TestContext{
		ctrl:         ctrl,
		echoMock:     mock.NewMockContext(ctrl),
		authMock:     authMock,
		oauthMock:    oauthMock,
		contractMock: contractMock,
		notaryMock:   notaryMock,
		wrapper:      Wrapper{Auth: authMock},
	}
}
