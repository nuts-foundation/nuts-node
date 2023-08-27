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
	result := CredentialInfo{
		ID: cred.ID.String(),
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
