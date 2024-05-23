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

package usersession

import (
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"time"
)

// Data is a session-bound Verifiable Credential wallet.
type Data struct {
	// Save is a function that persists the session.
	Save func() error `json:"-"`
	// TenantDID is the requesting DID when the user session was created, typically the employer's (of the user) DID.
	// A session needs to be scoped to the tenant DID, since the session gives access to the tenant's wallet,
	// and the user session might contain session-bound credentials (e.g. EmployeeCredential) that were issued by the tenant.
	TenantDID did.DID    `json:"tenantDID"`
	Wallet    UserWallet `json:"wallet"`
	ExpiresAt time.Time  `json:"expiresAt"`
}

// UserWallet is a session-bound Verifiable Credential wallet.
// It's an in-memory wallet which contains the user's private key in plain text.
// This is OK, since the associated credentials are intended for protocol compatibility (OpenID4VP with a low-assurance EmployeeCredential),
// when an actual user wallet is involved, this wallet isn't used.
type UserWallet struct {
	Credentials []vc.VerifiableCredential
	// JWK is an in-memory key pair associated with the user's wallet in JWK form.
	JWK []byte
	// DID is the did:jwk DID of the user's wallet.
	DID did.DID
}

// Key returns the JWK as jwk.Key
func (w UserWallet) Key() (jwk.Key, error) {
	set, err := jwk.Parse(w.JWK)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}
	result, available := set.Key(0)
	if !available {
		return nil, errors.New("expected exactly 1 key in the JWK set")
	}
	return result, nil
}
