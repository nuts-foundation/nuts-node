/*
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

package v1

import (
	"github.com/nuts-foundation/nuts-node/core"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/stretchr/testify/assert"
)

func TestHTTPClient_UpdateContactInformation(t *testing.T) {
	info := ContactInformation{
		Email:   "email",
		Name:    "name",
		Phone:   "phone",
		Website: "website",
	}
	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK, ResponseData: info})
		c := getClient(s)
		err := c.UpdateContactInformation("abc", info)
		assert.NoError(t, err)
	})
	t.Run("error - server error", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: ""})
		c := getClient(s)
		err := c.UpdateContactInformation("def", info)
		assert.Error(t, err)
	})
	t.Run("error - wrong address", func(t *testing.T) {
		c := HTTPClient{
			ClientConfig: core.ClientConfig{
				Address: "not_an_address", Timeout: time.Second},
		}
		err := c.UpdateContactInformation("def", info)
		assert.Error(t, err)
	})
}

func TestHTTPClient_GetContactInformation(t *testing.T) {
	expected := ContactInformation{
		Email:   "email",
		Name:    "name",
		Phone:   "phone",
		Website: "website",
	}
	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK, ResponseData: expected})
		c := getClient(s)
		actual, err := c.GetContactInformation("abc")
		assert.NoError(t, err)
		assert.Equal(t, expected, *actual)
	})
	t.Run("no contact info", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusNotFound, ResponseData: nil})
		c := getClient(s)
		actual, err := c.GetContactInformation("abc")
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
	t.Run("error", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: nil})
		c := getClient(s)
		actual, err := c.GetContactInformation("abc")
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestHTTPClient_AddEndpoint(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		endpoint := Endpoint{
			ServiceEndpoint: "ref:did:nuts:455/serviceEndpoint?type=eOverdracht-production",
			ID:              ssi.MustParseURI("did:nuts:123#abc"),
			Type:            "eOverdracht",
		}
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK, ResponseData: endpoint})
		c := getClient(s)
		res, err := c.AddEndpoint("did:nuts:123", "type", "some-url")
		assert.NoError(t, err)
		assert.Equal(t, endpoint, *res)
	})
	t.Run("error - server error", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: ""})
		c := getClient(s)
		endpoint, err := c.AddEndpoint("abc", "type", "some-url")
		assert.EqualError(t, err, "server returned HTTP 500 (expected: 200)")
		assert.Nil(t, endpoint)
	})
	t.Run("error - wrong address", func(t *testing.T) {
		c := HTTPClient{
			ClientConfig: core.ClientConfig{
				Address: "not_an_address", Timeout: time.Second},
		}
		endpoint, err := c.AddEndpoint("abc", "type", "some-url")
		assert.Regexp(t, `no such host|Temporary failure in name resolution`, err.Error())
		assert.Nil(t, endpoint)
	})
}

func TestHTTPClient_DeleteEndpointsByType(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusNoContent})
		c := getClient(s)
		err := c.DeleteEndpointsByType("did:nuts:123", "eOverdracht")
		assert.NoError(t, err)
	})
	t.Run("error - server error", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusInternalServerError})
		c := getClient(s)
		err := c.DeleteEndpointsByType("did:nuts:123", "eOverdracht")
		assert.EqualError(t, err, "server returned HTTP 500 (expected: 204)")
	})
	t.Run("error - wrong address", func(t *testing.T) {
		c := HTTPClient{
			ClientConfig: core.ClientConfig{
				Address: "not_an_address", Timeout: time.Second},
		}
		err := c.DeleteEndpointsByType("did:nuts:123", "eOverdracht")
		assert.Regexp(t, `no such host|Temporary failure in name resolution`, err.Error())
	})
}

func TestHTTPClient_AddCompoundService(t *testing.T) {
	refs := map[string]string{
		"foo": "bar",
	}
	t.Run("ok", func(t *testing.T) {
		res := &CompoundService{
			ID:              ssi.MustParseURI("abc#123"),
			ServiceEndpoint: map[string]interface{}{"foo": "bar"},
			Type:            "type",
		}

		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK, ResponseData: res})
		c := getClient(s)
		cs, err := c.AddCompoundService("abc", "type", refs)
		assert.NoError(t, err)
		assert.Equal(t, res, cs)
	})
	t.Run("error - server error", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: ""})
		c := getClient(s)
		_, err := c.AddCompoundService("abc", "type", refs)
		assert.Error(t, err)
	})
	t.Run("error - wrong address", func(t *testing.T) {
		c := HTTPClient{
			ClientConfig: core.ClientConfig{
				Address: "not_an_address", Timeout: time.Second},
		}
		_, err := c.AddCompoundService("abc", "type", refs)
		assert.Error(t, err)
	})
}

func TestHTTPClient_DeleteService(t *testing.T) {
	id := ssi.MustParseURI("did:123#abc")
	t.Run("ok", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusNoContent})
		c := getClient(s)
		err := c.DeleteService(id)
		assert.NoError(t, err)
	})

	t.Run("error - internal server error", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: nil})
		c := getClient(s)
		err := c.DeleteService(id)
		assert.Error(t, err)
	})
	t.Run("error - wrong address", func(t *testing.T) {
		c := HTTPClient{
			ClientConfig: core.ClientConfig{
				Address: "not_an_address", Timeout: time.Second},
		}
		err := c.DeleteService(id)
		assert.Error(t, err)
	})
}

func TestHTTPClient_GetCompoundServices(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cServices := []CompoundService{{
			ID:              ssi.MustParseURI("did:nuts:123#abc"),
			ServiceEndpoint: map[string]interface{}{"auth": "did:nuts:123/serviceEndpoint?type=token-server"},
			Type:            "eOverdracht",
		}}
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK, ResponseData: cServices})
		c := getClient(s)
		res, err := c.GetCompoundServices("did:nuts:123")
		assert.NoError(t, err)
		assert.Equal(t, cServices, res)
	})
	t.Run("error - internal server error", func(t *testing.T) {
		s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: nil})
		c := getClient(s)
		res, err := c.GetCompoundServices("did:nuts:123")
		assert.Error(t, err)
		assert.EqualError(t, err, "server returned HTTP 500 (expected: 200)")
		assert.Nil(t, res)
	})
	t.Run("error - wrong address", func(t *testing.T) {
		c := HTTPClient{
			ClientConfig: core.ClientConfig{
				Address: "not_an_address", Timeout: time.Second},
		}
		res, err := c.GetCompoundServices("did:nuts:123")
		assert.Regexp(t, `no such host|Temporary failure in name resolution`, err.Error())
		assert.Nil(t, res)
	})

}

func getClient(s *httptest.Server) HTTPClient {
	return HTTPClient{ClientConfig: core.ClientConfig{Address: s.URL, Timeout: time.Second}}
}
