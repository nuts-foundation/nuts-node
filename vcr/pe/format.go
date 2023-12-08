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

package pe

import "github.com/nuts-foundation/go-did/vc"

// ChooseVPFormat determines the format of the Verifiable Presentation based on the authorization server metadata.
func ChooseVPFormat(formats map[string]map[string][]string) string {
	// They are in preferred order
	if _, ok := formats[vc.JWTPresentationProofFormat]; ok {
		return vc.JWTPresentationProofFormat
	}
	if _, ok := formats["jwt_vp_json"]; ok {
		return vc.JWTPresentationProofFormat
	}
	if _, ok := formats[vc.JSONLDPresentationProofFormat]; ok {
		return vc.JSONLDPresentationProofFormat
	}
	return ""
}
