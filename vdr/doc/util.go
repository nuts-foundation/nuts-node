package doc

import (
	"fmt"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"strings"
)

const serviceTypeQueryParameter = "type"
const serviceEndpointPath = "serviceEndpoint"

func MakeServiceReference(subjectDID did.DID, serviceType string) ssi.URI {
	ref := subjectDID.URI()
	ref.Fragment = ""
	ref.Path = "/" + serviceEndpointPath
	ref.RawPath = "/" + serviceEndpointPath
	ref.RawQuery = fmt.Sprintf("%s=%s", serviceTypeQueryParameter, serviceType)
	return ref
}

// IsServiceReference checks whether the given endpoint string looks like a service reference (e.g. did:nuts:1234/serviceType?type=HelloWorld).
func IsServiceReference(endpoint string) bool {
	return strings.HasPrefix(endpoint, "did:")
}

func ValidateServiceReference(endpointURI ssi.URI) error {
	// Parse it as DID URL since DID URLs are rootless and thus opaque (RFC 3986), meaning the path will be part of the URI body, rather than the URI path.
	// For DID URLs the path is parsed properly.
	didEndpointURL, err := did.ParseDIDURL(endpointURI.String())
	if err != nil {
		return types.ErrInvalidServiceQuery
	}
	if didEndpointURL.Path != serviceEndpointPath {
		// Service reference doesn't refer to `/serviceEndpoint`
		return types.ErrInvalidServiceQuery
	}
	queriedServiceType := endpointURI.Query().Get(serviceTypeQueryParameter)
	if len(queriedServiceType) == 0 {
		// Service reference doesn't contain `type` query parameter
		return types.ErrInvalidServiceQuery
	}
	if len(endpointURI.Query()[serviceTypeQueryParameter]) > 1 {
		// Service reference contains more than 1 `type` query parameter
		return types.ErrInvalidServiceQuery
	}
	if len(endpointURI.Query()) > 1 {
		// Service reference contains more than just `type` query parameter
		return types.ErrInvalidServiceQuery
	}
	return nil
}
