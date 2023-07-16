package didweb

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MethodName is the DID method name used by did:web
const MethodName = "web"

var _ types.DIDResolver = (*Resolver)(nil)

// Resolver is a DID resolver for the did:web method.
type Resolver struct {
	HttpClient *http.Client
}

// NewResolver creates a new did:web Resolver with default TLS configuration.
func NewResolver() *Resolver {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	return &Resolver{
		HttpClient: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		},
	}
}

// Resolve implements the DIDResolver interface.
func (w Resolver) Resolve(id did.DID, _ *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	if id.Method != "web" {
		return nil, nil, errors.New("DID is not did:web")
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

	ct, _, err := mime.ParseMediaType(httpResponse.Header.Get("Content-Type"))
	if err != nil {
		return nil, nil, fmt.Errorf("did:web invalid content-type: %w", err)
	}
	switch ct {
	case "application/did+ld+json":
		// We don't do JSON-LD processing, as the spec suggests we may do when encountering a JSON-LD DID document.
		// Reason is we currently don't see use cases for custom JSON-LD contexts adding information (e.g. aliasing fields or values)
		// to the DID document that breaks the interpretation of the DID document, when we don't actually process it as JSON-LD.
		// Maybe a future use case would be defining custom verification methods (e.g. obscure key types),
		// but those won't be supported out of the box by the Nuts node anyway, so no need to understand those.
		fallthrough
	case "application/did+json":
		fallthrough
	case "application/json":
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
