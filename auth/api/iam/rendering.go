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

package iam

import (
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"sort"
	"strconv"
)

type CredentialInfoAttribute struct {
	Name  string
	Value string
}

type CredentialInfo struct {
	ID         string
	Type       []string
	Attributes []CredentialInfoAttribute
}

func makeCredentialInfo(cred vc.VerifiableCredential) CredentialInfo {
	result := CredentialInfo{}
	if cred.ID != nil {
		result.ID = cred.ID.String()
	}

	for _, curr := range cred.Type {
		if curr.String() != vc.VerifiableCredentialType {
			result.Type = append(result.Type, curr.String())
		}
	}

	// Collect all properties from the credential subject
	// This assumes it's a compacted JSON-LD document, with arrays compacted
	propsMap := map[string]interface{}{}
	for _, curr := range cred.CredentialSubject {
		asMap, ok := curr.(map[string]interface{})
		if ok {
			flatMap("", " ", asMap, propsMap)
		}
	}

	for key, value := range propsMap {
		if key == "id" {
			// omit ID attribute
			continue
		}
		result.Attributes = append(result.Attributes, CredentialInfoAttribute{
			Name:  key,
			Value: fmt.Sprintf("%s", value),
		})
	}
	sort.SliceStable(result.Attributes, func(i, j int) bool {
		return result.Attributes[i].Name < result.Attributes[j].Name
	})
	return result
}

func flatMap(path string, separator string, src map[string]interface{}, dest map[string]interface{}) {
	if len(path) > 0 {
		path += separator
	}
	for key, value := range src {
		switch next := value.(type) {
		case map[string]interface{}:
			flatMap(path+key, separator, next, dest)
		case []interface{}:
			for i := 0; i < len(next); i++ {
				dest[path+key+"."+strconv.Itoa(i)] = next[i]
			}
		default:
			dest[path+key] = value
		}
	}
}
