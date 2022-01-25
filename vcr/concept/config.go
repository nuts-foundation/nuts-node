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

package concept

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/tidwall/gjson"
)

// Config defines the concept configuration for a VerifiableCredential
type Config struct {
	// Concept groups multiple credentials under a single name
	Concept string `yaml:"concept"`
	// CredentialType defines the type of the credential. 'VerifiableCredential' is omitted.
	CredentialType string `yaml:"credentialType"`
	// Indices contains a set of Index values
	Indices []Index `yaml:"indices"`
	// Public indicates if this credential may be published on the DAG
	Public bool `yaml:"public"`
	// Template is the string template for outputting a credential to a common format
	// Each <<JSONPath>> value is substituted with the outcome of the JSONPath query
	Template *string `yaml:"template"`
}

var templateStringMatcher = regexp.MustCompile(`<<([a-zA-Z\\._\\-]+)>>`)

func (c Config) transform(vc vc.VerifiableCredential) (Concept, error) {
	vcBytes, err := json.Marshal(vc)
	vcString := string(vcBytes)
	concept := Concept{}
	var template string
	if err != nil {
		return nil, err
	}

	// if no template is present, we'll return the credential
	if c.Template == nil {
		template = vcString
	} else {
		template = *c.Template

		// find all << refs >>
		for _, match := range templateStringMatcher.FindAllStringSubmatch(template, -1) {
			replacement := gjson.Get(vcString, match[1]).String()
			replacee := match[0]
			template = strings.ReplaceAll(template, replacee, replacement)
		}
	}

	err = json.Unmarshal([]byte(template), &concept)
	return concept, err
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
	// Alias defines an optional alias that can be used within a search query
	Alias *string `yaml:"alias"`
	// JSONPath defines the JSON search path
	JSONPath string `yaml:"path"`
	// Tokenizer defines an optional tokenizer. Possible values: [whitespace]
	Tokenizer *string `yaml:"tokenizer"`
	// Transformer defines an optional transformer. Possible values: [cologne, lowercase]
	Transformer *string `yaml:"transformer"`
}
