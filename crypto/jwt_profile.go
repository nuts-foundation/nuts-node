/*
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

package crypto

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
)

// JWTValidator is a function that performs additional validation on a parsed JWT token.
// It receives the token and its protected headers.
type JWTValidator func(token jwt.Token, headers map[string]interface{}) error

// DefaultJWTClockSkew is the baseline clock skew tolerance applied during JWT validation
// when a profile does not specify its own. It guards against small clock drift between
// issuer and verifier; production deployments with a known wider drift should override
// via JWTProfile.ClockSkew (typically set from a configured value, e.g. auth.clockskew).
const DefaultJWTClockSkew = 5 * time.Second

// JWTProfile defines the validation requirements for a specific type of JWT.
type JWTProfile struct {
	// Typ is the required value of the JWT typ header. Empty means no check.
	Typ string
	// RequiredClaims lists claims that must be present and non-empty.
	RequiredClaims []string
	// MaxValidity is the maximum allowed duration between exp and iat. Zero means no check.
	MaxValidity time.Duration
	// ClockSkew is the acceptable clock skew for time-based claims (exp, iat, nbf).
	// Zero means DefaultJWTClockSkew is used.
	ClockSkew time.Duration
	// Validators are additional checks run after parsing and standard validation.
	Validators []JWTValidator
}

// WithMaxValidity returns a copy of the profile with the given MaxValidity.
// Useful for callers that need to override the default max validity from a
// shared base profile (e.g. to honor a configured access token lifespan).
func (p JWTProfile) WithMaxValidity(d time.Duration) *JWTProfile {
	p.MaxValidity = d
	return &p
}

// WithClockSkew returns a copy of the profile with the given ClockSkew.
// Callers that receive an operator-configured skew (e.g. auth.clockskew) use this
// to override the profile's default without mutating the shared base profile.
func (p JWTProfile) WithClockSkew(d time.Duration) *JWTProfile {
	p.ClockSkew = d
	return &p
}

// IssuerKidValidator checks that the iss claim matches the DID extracted from the kid header.
// When kid is empty, the check is skipped (VC data model v1 compatibility).
func IssuerKidValidator(token jwt.Token, headers map[string]interface{}) error {
	kid, _ := headers["kid"].(string)
	if kid == "" {
		return nil
	}
	parsed, err := did.ParseDIDURL(kid)
	if err != nil {
		return fmt.Errorf("invalid kid header: %w", err)
	}
	if parsed.DID.String() != token.Issuer() {
		return fmt.Errorf("token issuer (%s) does not match signing key DID (%s)", token.Issuer(), parsed.DID.String())
	}
	return nil
}
