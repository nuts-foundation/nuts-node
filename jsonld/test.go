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

var jsonLDExample = `
{
  "@context": {
    "id": "@id",
    "type": "@type",
    "schema": "http://example.com/",
    "Person": {
      "@id": "schema:Person",
      "@context": {
        "id": "@id",
        "type": "@type",
        "name": {"@id": "schema:name"},
        "telephone": {"@id": "schema:telephone", "@container": "@list"},
        "url": {"@id": "schema:url", "@type": "@id"},
        "children": {"@id": "schema:children", "@container": "@list"},
		"parents": {"@id": "schema:parents"}
      }
    }
  },
  "@type": "Person",
  "@id": "123456782",
  "name": "Jane Doe",
  "url": "http://www.janedoe.com",
  "telephone": ["06-12345678", "06-87654321"],
  "children": [{
    "@type": "Person",
    "name": "John Doe",
	"url": "http://www.johndoe.org"
  }],
  "parents": [{
    "@type": "Person",
    "name": "John Doe",
	"url": "http://www.johndoe.org"
  }]
}
`

var invalidJSONLD = `
{
  "@context": [
    {
      "@version": 1.2
      
    }
  ]
}
`
