/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package http

import (
	"github.com/nuts-foundation/nuts-node/json"
	"io"
	"net/http"
	"net/url"
)

// Handler is a custom http handler useful in testing.
// Usage:
//
//	s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: someStruct})
//
// Then s.URL must be configured in the client.
type Handler struct {
	Request        *http.Request
	RequestHeaders http.Header
	RequestQuery   url.Values
	StatusCode     int
	RequestData    []byte
	ResponseData   interface{}
	ResponseHeader http.Header
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	h.Request = req
	h.RequestData, _ = io.ReadAll(req.Body)
	h.RequestHeaders = req.Header.Clone()
	h.RequestQuery = req.URL.Query()

	var bytes []byte
	if s, ok := h.ResponseData.(string); ok {
		bytes = []byte(s)
	} else {
		writer.Header().Add("Content-Type", "application/json")
		bytes, _ = json.Marshal(h.ResponseData)
	}

	for k, v := range h.ResponseHeader {
		writer.Header().Add(k, v[0])
	}
	writer.WriteHeader(h.StatusCode)
	_, _ = writer.Write(bytes)
}
