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

package iam

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"net/url"
)

type Session struct {
	ClientID      string                     `json:"client_id,omitempty"`
	Scope         []string                   `json:"scope"`
	OwnDID        did.DID                    `json:"own_did,omitempty"`
	RedirectURI   string                     `json:"redirect_uri,omitempty"`
	ServerState   map[string]interface{}     `json:"server_state,omitempty"`
	IDToken       *vc.VerifiablePresentation `json:"id_token,omitempty"`
	VPToken       *vc.VerifiablePresentation `json:"vp_token,omitempty"`
	ResponseType  []string                   `json:"response_type,omitempty"`
	RequestObject string                     `json:"request_object,omitempty"`
}

func AddQueryParams(u url.URL, params map[string]string) url.URL {
	values := u.Query()
	for key, value := range params {
		values.Add(key, value)
	}
	u.RawQuery = values.Encode()
	return u
}

func (s Session) CreateRedirectURI(params map[string]string) string {
	redirectURI, _ := url.Parse(s.RedirectURI)
	r := AddQueryParams(*redirectURI, params)
	return r.String()
}
