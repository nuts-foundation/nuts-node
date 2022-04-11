/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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

package jsonld

import (
<<<<<<< HEAD
=======
	"github.com/nuts-foundation/go-did/vc"
>>>>>>> added jsonld engine
	"github.com/piprate/json-gold/ld"
)

// ContextManager manages the different JSON-LD contexts. It helps in using the same loaded contexts over different engines.
type ContextManager interface {
<<<<<<< HEAD
	// DocumentLoader returns the JSON-LD DocumentLoader
	DocumentLoader() ld.DocumentLoader
=======
	// DocumentLoader returns the JSON-LD documentLoader
	DocumentLoader() ld.DocumentLoader
	// Transformer returns a transformer loaded with the correct JSON-LD contexts
	Transformer() Transformer
}

// Transformer helps in transforming different formats to a JSON-LD Document.
type Transformer interface {
	// FromVC transforms a nuts-foundation/go-did VerifiableCredential to a Document (expanded JSON-LD)
	FromVC(credential vc.VerifiableCredential) (Document, error)
	// FromBytes transforms a string representing a VerifiableCredential to a Document (expanded JSON-LD)
	FromBytes(asJSON []byte) (Document, error)
>>>>>>> added jsonld engine
}
