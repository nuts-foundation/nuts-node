/*
 * Nuts node
 * Copyright (C) 2026 Nuts community
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

package openid4vci

// ErrorCode is an OpenID4VCI 1.0 (ID-1) error code as defined in §8.3.1.2
// (Credential Endpoint) and §6.4 (Token Endpoint).
type ErrorCode string

const (
	// InvalidNonce means at least one of the key proofs in the Credential
	// Request contained an invalid c_nonce. Per §8.3.1.2 the wallet should
	// retrieve a new c_nonce from the Nonce Endpoint (§7) and may retry.
	InvalidNonce ErrorCode = "invalid_nonce"
)

// Error is a wire-format error returned by an OpenID4VCI endpoint.
// Specified by §6.4 and §8.3.
type Error struct {
	Code       ErrorCode `json:"error"`
	Err        error     `json:"-"`
	StatusCode int       `json:"-"`
}

// Error implements the error interface.
func (e Error) Error() string {
	if e.Err == nil {
		return string(e.Code)
	}
	return string(e.Code) + " - " + e.Err.Error()
}
