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

package holder

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
)

// PresentationOptions contains parameters used to create the right VerifiablePresentation
// It's up to the caller to make sure the AdditionalTypes are covered by the AdditionalContexts
type PresentationOptions struct {
	// AdditionalContexts contains the contexts to be added in addition to https://www.w3.org/2018/credentials/v1 and the context for JSONWebSignature2020
	AdditionalContexts []ssi.URI
	// AdditionalTypes contains the VerifiablePresentation types in addition to VerifiablePresentation
	AdditionalTypes []ssi.URI
	// ProofOptions contains the options for a specific proof.
	ProofOptions proof.ProofOptions
}
