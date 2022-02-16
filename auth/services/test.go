/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

package services

import "github.com/nuts-foundation/nuts-node/auth/contract"

type TestVPVerificationResult struct {
	Val         contract.State
	Type        string
	DAttributes map[string]string
	CAttributes map[string]string
}

func (t TestVPVerificationResult) Validity() contract.State {
	return t.Val
}

func (t TestVPVerificationResult) VPType() string {
	return t.Type
}

func (t TestVPVerificationResult) DisclosedAttribute(key string) string {
	return t.DAttributes[key]
}

func (t TestVPVerificationResult) ContractAttribute(key string) string {
	return t.CAttributes[key]
}

func (t TestVPVerificationResult) DisclosedAttributes() map[string]string {
	return t.DAttributes
}

func (t TestVPVerificationResult) ContractAttributes() map[string]string {
	return t.CAttributes
}
