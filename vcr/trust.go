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

package vcr

import (
	"errors"
	"os"
	"sync"

	"github.com/ghodss/yaml"
	"github.com/nuts-foundation/go-did"
)

var mutex = sync.Mutex{}

type trustConfig struct {
	filename      string
	issuesPerType map[string][]string
}

// Load the trusted issuers per credential type from file
func (tc trustConfig) Load() error {
	mutex.Lock()
	defer mutex.Unlock()

	if tc.filename == "" {
		return errors.New("trust config file not loaded")
	}

	// ignore if not exists
	_, err := os.Stat(tc.filename)
	if err != nil {
		return nil
	}

	data, err := os.ReadFile(tc.filename)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, &tc.issuesPerType)
}

// Save the list of trusted issuers per credential type to file
func (tc trustConfig) Save() error {
	mutex.Lock()
	defer mutex.Unlock()

	if tc.filename == "" {
		return errors.New("no filename specified")
	}

	data, err := yaml.Marshal(tc.issuesPerType)
	if err != nil {
		return err
	}

	return os.WriteFile(tc.filename, data, 0644)
}

// IsTrusted returns true when the given issuer is in the trusted issuers list of the given credentialType
func (tc trustConfig) IsTrusted(credentialType did.URI, issuer did.URI) bool {
	issuerString := issuer.String()
	for _, i := range tc.issuesPerType[credentialType.String()] {
		if i == issuerString {
			return true
		}
	}

	return false
}

// AddTrust adds trust in a specific Issuer for a credential type.
// It returns an error if the Save fails
func (tc trustConfig) AddTrust(credentialType did.URI, issuer did.URI) error {
	tString := credentialType.String()

	// to prevent duplicates
	issuerSet := map[string]bool{
		issuer.String(): true,
	}
	for _, i := range tc.issuesPerType[tString] {
		issuerSet[i] = true
	}
	j := 0
	var issuerList = make([]string, len(issuerSet))
	for k := range issuerSet {
		issuerList[j] = k
		j++
	}

	tc.issuesPerType[tString] = issuerList

	return tc.Save()
}

// RemoveTrust removes trust in a specific Issuer for a credential type.
// It returns an error if the Save fails
func (tc trustConfig) RemoveTrust(credentialType did.URI, issuer did.URI) error {
	tString := credentialType.String()

	// to prevent duplicates
	issuerSet := map[string]bool{}
	for _, i := range tc.issuesPerType[tString] {
		issuerSet[i] = true
	}
	delete(issuerSet, issuer.String())

	j := 0
	var issuerList = make([]string, len(issuerSet))
	for k := range issuerSet {
		issuerList[j] = k
		j++
	}

	tc.issuesPerType[tString] = issuerList

	return tc.Save()
}
