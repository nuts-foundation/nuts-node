package v1

import (
	"context"
	"io"
	"net/http"
	"time"
)

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	ServerAddress string
	Timeout       time.Duration
}

func (H HTTPClient) GetContactInformation(ctx context.Context, did string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	panic("implement me")
}

func (H HTTPClient) UpdateContactInformationWithBody(ctx context.Context, did string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	panic("implement me")
}

func (H HTTPClient) UpdateContactInformation(ctx context.Context, did string, body UpdateContactInformationJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	panic("implement me")
}

func (H HTTPClient) AddEndpointWithBody(ctx context.Context, did string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	panic("implement me")
}

func (H HTTPClient) AddEndpoint(ctx context.Context, did string, body AddEndpointJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	panic("implement me")
}

func (H HTTPClient) DeleteService(ctx context.Context, id string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	panic("implement me")
}

