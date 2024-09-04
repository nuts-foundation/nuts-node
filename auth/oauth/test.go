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

package oauth

// NewTokenResponse is a convenience function for creating a TokenResponse with the given parameters.
// expires_in and scope are only set if they are passed a valid value.
func NewTokenResponse(accessToken, tokenType string, expiresIn int, scope string, dpopKid string) *TokenResponse {
	tr := &TokenResponse{
		AccessToken: accessToken,
		TokenType:   tokenType,
	}
	if expiresIn > 0 {
		tr.ExpiresIn = &expiresIn
	}
	if scope != "" {
		tr.Scope = &scope
	}
	if dpopKid != "" {
		tr.DPoPKid = &dpopKid
	}
	return tr
}
