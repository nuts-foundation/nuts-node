package didion

import (
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"io"
	"net/http"
	"net/url"
)

var _ resolver.DIDResolver = &UniversalResolver{}

type ResolutionResult struct {
	Document did.Document              `json:"didDocument"`
	Metadata resolver.DocumentMetadata `json:"didDocumentMetadata"`
}

type UniversalResolver struct {
}

func (u UniversalResolver) Resolve(id did.DID, metadata *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error) {
	requestURL, _ := url.Parse("https://dev.uniresolver.io/1.0/identifiers/")
	httpResponse, err := http.Get(requestURL.JoinPath(url.PathEscape(id.String())).String())
	if err != nil {
		return nil, nil, fmt.Errorf("universal resolver failure: %w", err)
	}
	if httpResponse.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("universal resolver failure: %s", httpResponse.Status)
	}
	data, err := io.ReadAll(httpResponse.Body)
	println(string(data))
	if err != nil {
		return nil, nil, fmt.Errorf("universal resolver failure: %w", err)
	}
	return unmarshalResult(data)
}

func unmarshalResult(data []byte) (*did.Document, *resolver.DocumentMetadata, error) {
	intermediate := map[string]interface{}{}
	err := json.Unmarshal(data, &intermediate)
	if err != nil {
		return nil, nil, fmt.Errorf("universal resolver result unmarshal failure: %w", err)
	}

	didDocument := intermediate["didDocument"]
	// If @context contains objects, remove them since go-did can't handle them
	if ctx, ok := didDocument.(map[string]interface{})["@context"]; ok {
		if ctxEntry, ok := ctx.([]interface{}); ok {
			for i, item := range ctxEntry {
				if _, ok := item.(string); !ok {
					ctxEntry[i] = nil
				}
			}
		}
	}

	j, _ := json.Marshal(didDocument)
	result := ResolutionResult{}
	err = json.Unmarshal(j, &result.Document)
	if err != nil {
		return nil, nil, fmt.Errorf("universal resolver result unmarshal failure: %w", err)
	}
	return &result.Document, &result.Metadata, nil
}
