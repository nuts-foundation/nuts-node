package model

import "github.com/nuts-foundation/go-did/vc"

// PresentationsResponse is the response for the GetPresentations endpoint.
type PresentationsResponse struct {
	Entries []vc.VerifiablePresentation `json:"entries"`
	Tag     string                      `json:"tag"`
}
