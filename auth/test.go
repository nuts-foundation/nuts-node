/*
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
 *
 */

package auth

import (
	"github.com/nuts-foundation/nuts-node/vdr"
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/vcr"
	"go.uber.org/mock/gomock"
)

func TestConfig() Config {
	config := DefaultConfig()
	config.ContractValidators = []string{"dummy"}
	return config
}

func testInstance(t *testing.T, cfg Config) *Auth {
	cryptoInstance := crypto.NewMemoryCryptoInstance(t)
	vcrInstance := vcr.NewTestVCRInstance(t)
	ctrl := gomock.NewController(t)
	pkiMock := pki.NewMockProvider(ctrl)
	pkiMock.EXPECT().AddTruststore(gomock.Any()).AnyTimes()
	pkiMock.EXPECT().CreateTLSConfig(gomock.Any()).AnyTimes()
	vdrInstance := vdr.NewMockVDR(ctrl)
	vdrInstance.EXPECT().Resolver().AnyTimes()
	return NewAuthInstance(cfg, vdrInstance, vcrInstance, cryptoInstance, nil, nil, pkiMock)
}
