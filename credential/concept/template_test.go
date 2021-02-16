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

package concept

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"
)

func TestTemplateString_isValid(t *testing.T) {
	cases := []struct {
		tString  templateString
		expected bool
		title    string
	}{
		{"subject", true, "ok - basic string"},
		{"<<subject>>", true, "ok - concept string"},
		{"subject@{2_2}", true, "ok - basic with single index"},
		{"<<subject>>@{2_2}", true, "ok - concept with single index"},
		{"subject@{2_2},{1_1}", true, "ok - basic with dual index"},
		{"<<subject>>@{2_2},{1_1}", true, "ok - concept with dual index"},
		{"subject@{2_2_2}", false, "error - triple index layer"},
		{"subject@", false, "error - missing index"},
		{"<<subject", false, "error - missing concept postfix"},
		{"subject>>", false, "error - missing concept prefix"},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			assert.Equal(t, c.expected, c.tString.isValid())
		})
	}
}

func TestTemplate_parse(t *testing.T) {
	ct := template{
		raw: ExampleTemplate,
	}
	if !assert.NoError(t, ct.parse()) {
		return
	}

	t.Run("it adds the correct mappings", func(t *testing.T) {
		assert.Len(t, ct.conceptIndexMapping, 6)

		assert.Equal(t, "id", ct.ToVCPath("id"))
		assert.Equal(t, "credentialSubject.id", ct.conceptIndexMapping["subject"])
		assert.Equal(t, "issuer", ct.conceptIndexMapping["issuer"])
		assert.Equal(t, "credentialSubject.company.city", ct.conceptIndexMapping["company.city"])
		assert.Equal(t, "credentialSubject.company.name", ct.conceptIndexMapping["company.name"])
	})

	t.Run("it adds the correct fixed values", func(t *testing.T) {
		assert.Len(t, ct.fixedValues, 1)

		assert.Equal(t, ExampleType, ct.fixedValues["type"])
	})

	t.Run("it adds the correct Indices", func(t *testing.T) {
		assert.Len(t, ct.Indices(), 2)

		assert.Equal(t, "type", ct.indices[0][0])
		assert.Equal(t, "company.name", ct.indices[0][1])
		assert.Equal(t, "type", ct.indices[1][0])
		assert.Equal(t, "subject", ct.indices[1][1])
	})

	t.Run("error - incorrect syntax", func(t *testing.T) {
		var errorCred = template{raw: `{"id": "<<id>>@"}`}

		err := errorCred.parse()

		assert.Error(t, err)
	})

	t.Run("error - unsupported", func(t *testing.T) {
		var listCred = template{raw: `{"id": ["id"]}`}

		err := listCred.parse()

		assert.Error(t, err)
	})
}

func TestTemplate_transform(t *testing.T) {
	ct := template{
		raw: ExampleTemplate,
	}
	if !assert.NoError(t, ct.parse()) {
		return
	}

	t.Run("ok", func(t *testing.T) {
		testVC := did.VerifiableCredential{}
		if !assert.NoError(t, json.Unmarshal([]byte(TestCredential), &testVC)) {
			return
		}

		concept, err := ct.transform(testVC)
		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, concept)

		assert.Equal(t, "did:nuts:1#123", concept[IDField])
		assert.Equal(t, ExampleType, concept[TypeField])
		assert.Equal(t, "did:nuts:1", concept[IssuerField])
		assert.Equal(t, "did:nuts:2", concept[SubjectField])

		ce := concept["company"]
		assert.NotNil(t, ce)

		cem := ce.(Concept)
		assert.Equal(t, "Eibergen", cem["city"])
		assert.Equal(t, "Because we care BV", cem["name"])
	})

	t.Run("error - arrays not supported", func(t *testing.T) {
		var testCredential = `
{
	"id": "did:nuts:1#123",
	"issuer": "did:nuts:1",
	"type": ["VerifiableCredential", "ExampleCredential"],
	"credentialSubject": []
}
`
		testVC := did.VerifiableCredential{}
		if !assert.NoError(t, json.Unmarshal([]byte(testCredential), &testVC)) {
			return
		}

		_, err := ct.transform(testVC)
		assert.Error(t, err)
	})
}

func TestTemplate_concepts(t *testing.T) {
	ct := template{
		raw: ExampleTemplate,
	}
	if !assert.NoError(t, ct.parse()) {
		return
	}

	cs := ct.concepts()
	sort.Slice(cs, func(i, j int) bool {
		return strings.Compare(cs[i], cs[j]) < 0
	})

	assert.Len(t, cs, 2)
	assert.Equal(t, "company.name", cs[1])
	assert.Equal(t, "company.city", cs[0])

}
