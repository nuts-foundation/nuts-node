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

package crypto

import (
	"context"
	"github.com/nuts-foundation/nuts-node/crypto/dpop"
)

func (client *Crypto) SignDPoP(ctx context.Context, token dpop.DPoP, kid string) (string, error) {
	privateKey, kid, err := client.getPrivateKey(ctx, kid)
	if err != nil {
		return "", err
	}

	keyAsJWK, err := jwkKey(privateKey)
	if err != nil {
		return "", err
	}

	return token.Sign(keyAsJWK)
}
