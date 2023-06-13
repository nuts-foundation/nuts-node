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

package openid4vci

import (
	"github.com/nuts-foundation/go-did/vc"
	"time"
)

// Flow is an active OpenID4VCI credential issuance flow.
type Flow struct {
	ID string `json:"id"`
	// IssuerID is the identifier of the credential issuer.
	IssuerID string `json:"issuer_id"`
	// WalletID is the identifier of the wallet.
	WalletID string `json:"wallet_id"`
	// Grants is a list of grants that can be used to acquire an access token.
	Grants []Grant `json:"grants"`
	// Credentials is the list of Verifiable Credentials that be issued to the wallet through this flow.
	// It might be pre-determined (in the issuer-initiated flow) or determined during the flow execution (in the wallet-initiated flow).
	Credentials []vc.VerifiableCredential `json:"credentials"`
	Expiry      time.Time                 `json:"exp"`
}

// Nonce is a nonce that has been issued for an OpenID4VCI flow, to be used by the wallet when requesting credentials.
// A nonce can only be used once (doh), and is only valid for a certain period of time.
type Nonce struct {
	Nonce  string    `json:"nonce"`
	Expiry time.Time `json:"exp"`
}

// Grant is a grant that has been issued for an OAuth2 state.
type Grant struct {
	// Type is the type of grant, e.g. "urn:ietf:params:oauth:grant-type:pre-authorized_code".
	Type string `json:"type"`
	// Params is a map of parameters for the grant, e.g. "pre-authorized_code" for type "urn:ietf:params:oauth:grant-type:pre-authorized_code".
	Params map[string]interface{} `json:"params"`
}
