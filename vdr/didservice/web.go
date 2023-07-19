package didservice

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var _ types.DIDResolver = (*WebResolver)(nil)

// WebResolver is a DID resolver for the did:web method.
type WebResolver struct {
	HttpClient *http.Client
}

// NewWebResolver creates a new WebResolver with default TLS configuration.
func NewWebResolver() *WebResolver {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	return &WebResolver{
		HttpClient: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		},
	}
}

// Resolve implements the DIDResolver interface.
func (w WebResolver) Resolve(id did.DID, _ *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	if id.Method != "web" {
		return nil, nil, errors.New("only did:web is supported")
	}

	var baseID = id.ID
	var path string
	subpathIdx := strings.Index(id.ID, ":")
	if subpathIdx == -1 {
		path = "/.well-known/did.json"
	} else {
		// subpaths are encoded as / -> :
		baseID = id.ID[:subpathIdx]
		path = id.ID[subpathIdx:]
		path = strings.ReplaceAll(path, ":", "/") + "/did.json"
	}

	unescapedID, err := url.PathUnescape(baseID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid did:web: %w", err)
	}
	targetURL := "https://" + unescapedID + path

	// TODO: Support DNS over HTTPS (DOH), https://www.rfc-editor.org/rfc/rfc8484
	httpResponse, err := w.HttpClient.Get(targetURL)
	if err != nil {
		return nil, nil, fmt.Errorf("did:web HTTP error: %w", err)
	}
	defer httpResponse.Body.Close()
	if !(httpResponse.StatusCode >= 200 && httpResponse.StatusCode < 300) {
		return nil, nil, fmt.Errorf("did:web non-ok HTTP status: %s", httpResponse.Status)
	}

	ct := httpResponse.Header.Get("Content-Type")
	switch ct {
	case "application/did+ld+json":
		// TODO: Should we perform JSON-LD processing here, as stated by the spec?
		fallthrough
	case "application/did+json":
		// This is OK
	default:
		return nil, nil, fmt.Errorf("did:web unsupported content-type: %s", ct)
	}

	// Read document
	data, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("did:web HTTP response read error: %w", err)
	}
	var document did.Document
	err = document.UnmarshalJSON(data)
	if err != nil {
		return nil, nil, fmt.Errorf("did:web JSON unmarshal error: %w", err)
	}

	if !document.ID.Equals(id.WithoutURL()) {
		return nil, nil, fmt.Errorf("did:web document ID mismatch: %s != %s", document.ID, id.WithoutURL())
	}

	return &document, &types.DocumentMetadata{}, nil
}
