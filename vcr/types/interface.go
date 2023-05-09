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

package types

import (
	"github.com/nuts-foundation/go-did/vc"
	"time"
)

// Writer is the interface that groups al the VC write methods
type Writer interface {
	// StoreCredential writes a VC to storage. Before writing, it calls Verify!
	// It can handle duplicates.
	StoreCredential(vc vc.VerifiableCredential, validAt *time.Time) error
}
