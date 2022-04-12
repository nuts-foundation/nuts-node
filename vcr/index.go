/*
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

package vcr

// indexConfig is used to load the configured indices on the VCR
type indexConfig struct {
	// Indices contains a set of Index values
	Indices []Index `yaml:"indices"`
}

// Index for a credential
type Index struct {
	// Name identifies the index, must be unique per credential
	Name string `yaml:"name"`
	// Parts defines the individual index parts, the ordering is significant
	Parts []IndexPart `yaml:"parts"`
}

// IndexPart defines the JSONPath and type of index for a partial index within a compound index
type IndexPart struct {
	// IRIPath defines the JSON-LD search path
	IRIPath []string `yaml:"iriPath"`
	// Tokenizer defines an optional tokenizer. Possible values: [whitespace]
	Tokenizer *string `yaml:"tokenizer"`
	// Transformer defines an optional transformer. Possible values: [cologne, lowercase]
	Transformer *string `yaml:"transformer"`
}
