/*
 * Nuts crypto
 * Copyright (C) 2020. Nuts community
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
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
)

// ErrNotImplemented indicates that this client API call is not implemented.
var ErrNotImplemented = errors.New("operation not implemented")

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	ServerAddress string
	Timeout       time.Duration
}

func (hb HTTPClient) clientWithRequestEditor(fn RequestEditorFn) ClientInterface {
	url := hb.ServerAddress
	if !strings.Contains(url, "http") {
		url = fmt.Sprintf("http://%v", hb.ServerAddress)
	}

	response, err := NewClientWithResponses(url, WithRequestEditorFn(fn))
	if err != nil {
		panic(err)
	}
	return response
}

func (hb HTTPClient) client() ClientInterface {
	return hb.clientWithRequestEditor(nil)
}

// GetPublicKey returns a PrivateKey from the server given a kid
func (hb HTTPClient) GetPublicKey(kid string) (jwk.Key, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hb.Timeout)
	defer cancel()
	httpClient := hb.clientWithRequestEditor(func(ctx context.Context, req *http.Request) error {
		req.Header.Add("Accept", "application/json")
		return nil
	})
	response, err := httpClient.PublicKey(ctx, kid)
	if err != nil {
		return nil, err
	}
	if err := testResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	jwkSet, err := jwk.Parse(response.Body)
	if err != nil {
		return nil, err
	}
	return jwkSet.Keys[0], nil
}

func testResponseCode(expectedStatusCode int, response *http.Response) error {
	if response.StatusCode != expectedStatusCode {
		responseData, _ := ioutil.ReadAll(response.Body)
		return fmt.Errorf("server returned HTTP %d (expected: %d), response: %s",
			response.StatusCode, expectedStatusCode, string(responseData))
	}
	return nil
}
