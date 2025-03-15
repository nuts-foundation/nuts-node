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

package http

import (
	"github.com/nuts-foundation/nuts-node/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func GetResponseBodyBytes(t *testing.T, visitor func(http.ResponseWriter) error) []byte {
	recorder := httptest.NewRecorder()
	if err := visitor(recorder); err != nil {
		t.Fatal(err)
	}
	return recorder.Body.Bytes()
}

func GetResponseBody(t *testing.T, visitor func(http.ResponseWriter) error) string {
	return string(GetResponseBodyBytes(t, visitor))
}

func UnmarshalResponseBody(t *testing.T, visitor func(http.ResponseWriter) error, target interface{}) {
	data := GetResponseBodyBytes(t, visitor)
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}
