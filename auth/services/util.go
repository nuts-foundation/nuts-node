package services

import (
	"crypto"
	"fmt"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"time"
)

// ResolveSigningKeyID looks up a signing key of the specified holder. It returns the ID
// of the found key. Typically used to find a key for signing one's own documents. If no suitable keys
// are found an error is returned.
func ResolveSigningKeyID(resolver types.DocResolver, holder did.DID, validAt *time.Time) (string, error) {
	doc, _, err := resolver.Resolve(holder, &types.ResolveMetadata{
		ResolveTime: validAt,
	})
	if err != nil {
		return "", err
	}
	if len(doc.AssertionMethod) == 0 {
		return "", fmt.Errorf("DID Document has no assertionMethod keys (did=%s)", holder)
	}
	return doc.AssertionMethod[0].ID.String(), nil
}

// ResolveSigningKey looks up a specific signing key and returns it as crypto.PublicKey. If the key can't be found
// or isn't meant for signing an error is returned.
func ResolveSigningKey(resolver types.DocResolver, keyID string, validAt *time.Time) (crypto.PublicKey, error) {
	kid, err := did.ParseDID(keyID)
	if err != nil {
		return nil, fmt.Errorf("invalid key ID (id=%s): %w", keyID, err)
	}
	holder := *kid
	holder.Fragment = ""
	doc, _, err := resolver.Resolve(holder, &types.ResolveMetadata{
		ResolveTime: validAt,
	})
	if err != nil {
		return "", err
	}
	var result *did.VerificationRelationship
	for _, rel := range doc.AssertionMethod {
		if rel.ID.String() == keyID {
			result = &rel
		}
	}
	if result == nil {
		return "", fmt.Errorf("signing key not found (id=%s)", keyID)
	}
	return result.PublicKey()
}

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
	var services []did.Service
	for _, service := range doc.Service {
		if service.Type == endpointType {
			services = append(services, service)
		}
	}
	if len(services) == 0 {
		return did.URI{}, "", fmt.Errorf("endpoint not found (did=%s, type=%s)", holder, endpointType)
	}
	if len(services) > 1 {
		return did.URI{}, "", fmt.Errorf("multiple endpoints found (did=%s, type=%s)", holder, endpointType)
	}
	err = services[0].UnmarshalServiceEndpoint(&endpointURL)
	if err != nil {
		return did.URI{}, "", fmt.Errorf("unable to unmarshal single URL from service (id=%s): %w", services[0].ID.String(), err)
	}
	return services[0].ID, endpointURL, nil
}
