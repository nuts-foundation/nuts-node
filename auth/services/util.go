package services

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"fmt"
	"time"
)

// ResolveServiceURL finds the endpoint with the given type of the given holder referenced from the given service, and unmarshals it as single URL.
// It returns the endpoint ID and URL, or an error if anything went wrong;
// - holder document can't be resolved,
// - service with given type doesn't exist,
// - multiple services match,
// - referenced service doesn't resolve.
// - referenced service not unique.
func ResolveServiceURL(resolver types.DocResolver, holder did.DID, serviceType string, endpointType string, validAt *time.Time) (ssi.URI, string, error) {
	doc, _, err := resolver.Resolve(holder, &types.ResolveMetadata{ResolveTime: validAt})
	if err != nil {
		return ssi.URI{}, "", err
	}

	compoundService, err := resolveCompoundService(*doc, serviceType)
	if err != nil {
		return ssi.URI{}, "", fmt.Errorf("service not found (did=%s, service=%s)", doc.ID, serviceType)
	}

	endpointReference, ok := compoundService[endpointType]
	if !ok {
		return ssi.URI{}, "", fmt.Errorf("endpointType for service not found (did=%s, service=%s, type=%s)", doc.ID, serviceType, endpointType)
	}
	refDID, err := ssi.ParseURI(endpointReference)
	if err != nil {
		return ssi.URI{}, "", err
	}

	uri, url, err := resolveEndpointURL(resolver, *refDID, validAt)
	if err != nil {
		return ssi.URI{}, "", fmt.Errorf("failed to resolve endpoint from service (did=%s, service=%s, type=%s)", doc.ID, endpointReference, endpointType)
	}

	return uri, url, nil
}

type compoundServiceType map[string]string

func resolveCompoundService(doc did.Document, serviceType string) (service compoundServiceType, err error) {
	cs := compoundServiceType{}
	var services []did.Service
	for _, service := range doc.Service {
		if service.Type == serviceType {
			services = append(services, service)
		}
	}
	if len(services) != 1 {
		return cs, fmt.Errorf("incorrect number of services (did=%s, service=%s)", doc.ID, serviceType)
	}

	services[0].UnmarshalServiceEndpoint(&cs)

	return cs, nil
}

func resolveEndpointURL(resolver types.DocResolver, serviceURI ssi.URI, validAt *time.Time) (ssi.URI, string, error) {
	serviceCopy := serviceURI
	serviceCopy.RawQuery = ""
	serviceDID, err := did.ParseDID(serviceCopy.String())
	if err != nil {
		return ssi.URI{}, "", err
	}

	typeQuery, ok := serviceURI.Query()["type"]
	if !ok {
		return ssi.URI{}, "", fmt.Errorf("incorrect type selector in service reference: %s", serviceURI.String())
	}
	if len(typeQuery) != 1 {
		return ssi.URI{}, "", fmt.Errorf("incorrect type selector in service reference: %s", serviceURI.String())
	}

	doc, _, err := resolver.Resolve(*serviceDID, &types.ResolveMetadata{ResolveTime: validAt})
	if err != nil {
		return ssi.URI{}, "", err
	}

	return doc.ResolveEndpointURL(typeQuery[0])
}