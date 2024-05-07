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

package oauth

import (
	"github.com/nuts-foundation/nuts-node/crypto/jwx"
)

// proofTypeValuesSupported contains a list of supported cipher suites for ldp_vc & ldp_vp presentation formats
// Recommended list of options https://w3c-ccg.github.io/ld-cryptosuite-registry/
var proofTypeValuesSupported = []string{"JsonWebSignature2020"}

// DefaultOpenIDSupportedFormats returns the OpenID formats supported by the Nuts node and is used in the
//   - Authorization Server's metadata field `vp_formats_supported`
//   - Client's metadata field `vp_formats`
//
// TODO: spec is very unclear about this part.
// See https://github.com/nuts-foundation/nuts-node/issues/2447
func DefaultOpenIDSupportedFormats() map[string]map[string][]string {
	return map[string]map[string][]string{
		"jwt_vp_json": {"alg_values_supported": jwx.SupportedAlgorithmsAsStrings()},
		"jwt_vc_json": {"alg_values_supported": jwx.SupportedAlgorithmsAsStrings()},
		"ldp_vc":      {"proof_type_values_supported": proofTypeValuesSupported},
		"ldp_vp":      {"proof_type_values_supported": proofTypeValuesSupported},
	}
}

// CallbackPath is the node specific callback for an OAuth flow. The full callback URL is constructed as
// <node_url>/iam/{id}/callback
const CallbackPath = "callback"
