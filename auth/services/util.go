package services

import (
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// ResolveEndpointURL finds the endpoint with the given type of the given holder and unmarshals it as single URL.
// It returns the endpoint ID and URL, or an error if anything went wrong;
// - holder document can't be resolved,
// - service with given type doesn't exist,
// - multiple services match,
// - serviceEndpoint isn't a string.
func ResolveEndpointURL(resolver types.DocResolver, holder did.DID, endpointType string, validAt *time.Time) (endpointID did.URI, endpointURL string, err error) {
	doc, _, err := resolver.Resolve(holder, &types.ResolveMetadata{ResolveTime: validAt})
	if err != nil {
		return did.URI{}, "", err
	}
	return doc.ResolveEndpointURL(endpointType)
}
