package client

import (
	"net/http"
)

func New() ClientInterface {
	httpClient := http.DefaultClient
	result, _ := NewClientWithResponses("", WithHTTPClient(httpClient))
	return result
}
