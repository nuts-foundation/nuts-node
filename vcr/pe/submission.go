package pe

import (
	"encoding/json"
	v2 "github.com/nuts-foundation/nuts-node/vcr/pe/schema/v2"
)

// PresentationSubmission describes how the VCs in the VP match the input descriptors in the PD
type PresentationSubmission struct {
	// Id is the id of the presentation submission, which is a UUID
	Id string `json:"id"`
	// DefinitionId is the id of the presentation definition that this submission is for
	DefinitionId string `json:"definition_id"`
	// DescriptorMap is a list of mappings from input descriptors to VCs
	DescriptorMap []InputDescriptorMappingObject `json:"descriptor_map"`
}

// InputDescriptorMappingObject
type InputDescriptorMappingObject struct {
	Id     string `json:"id"`
	Path   string `json:"path"`
	Format string `json:"format"`
}

// ParsePresentationSubmission validates the given JSON and parses it into a PresentationSubmission.
// It returns an error if the JSON is invalid or doesn't match the JSON schema for a PresentationSubmission.
func ParsePresentationSubmission(raw []byte) (*PresentationSubmission, error) {
	enveloped := `{"presentation_submission":` + string(raw) + `}`
	if err := v2.Validate([]byte(enveloped), v2.PresentationSubmission); err != nil {
		return nil, err
	}
	var result PresentationSubmission
	err := json.Unmarshal(raw, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
