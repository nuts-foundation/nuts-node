/*
 * Nuts node
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
 */

package selfsigned

import (
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"time"
)

func (v sessionStore) VerifyVP(_ vc.VerifiablePresentation, _ *time.Time) (contract.VPVerificationResult, error) {
	return selfsignedVerificationResult{}, nil
}

type selfsignedVerificationResult struct {
}

func (s selfsignedVerificationResult) Validity() contract.State {
	return contract.Invalid
}

func (s selfsignedVerificationResult) Reason() string {
	return "not yet implemented"
}

func (s selfsignedVerificationResult) VPType() string {
	return ""
}

func (s selfsignedVerificationResult) DisclosedAttribute(key string) string {
	return ""
}

func (s selfsignedVerificationResult) ContractAttribute(key string) string {
	return ""
}

func (s selfsignedVerificationResult) DisclosedAttributes() map[string]string {
	return map[string]string{}
}

func (s selfsignedVerificationResult) ContractAttributes() map[string]string {
	return map[string]string{}
}
