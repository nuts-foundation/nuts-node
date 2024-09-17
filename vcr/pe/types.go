/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

// Package pe stands for Presentation Exchange which includes Presentation Definition and Presentation Submission
package pe

import "errors"

var ErrNoCredentials = errors.New("missing credentials")

// PresentationDefinitionClaimFormatDesignations (replaces generated one)
type PresentationDefinitionClaimFormatDesignations map[string]map[string][]string

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
	Format     string                        `json:"format"`
	Id         string                        `json:"id"`
	Path       string                        `json:"path"`
	PathNested *InputDescriptorMappingObject `json:"path_nested,omitempty"`
}

// Constraints
type Constraints struct {
	Fields          []Field             `json:"fields,omitempty"`
	IsHolder        []*IsHolderItems    `json:"is_holder,omitempty"`
	LimitDisclosure string              `json:"limit_disclosure,omitempty"`
	SameSubject     []*SameSubjectItems `json:"same_subject,omitempty"`
	Statuses        *Statuses           `json:"statuses,omitempty"`
	SubjectIsIssuer string              `json:"subject_is_issuer,omitempty"`
}

// Frame
type Frame struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
}

// InputDescriptor
type InputDescriptor struct {
	Constraints *Constraints                                   `json:"constraints"`
	Format      *PresentationDefinitionClaimFormatDesignations `json:"format,omitempty"`
	Group       []string                                       `json:"group,omitempty"`
	Id          string                                         `json:"id"`
	Name        string                                         `json:"name,omitempty"`
	Purpose     string                                         `json:"purpose,omitempty"`
}

// IsHolderItems
type IsHolderItems struct {
	Directive string   `json:"directive"`
	FieldId   []string `json:"field_id"`
}

// PresentationDefinition
type PresentationDefinition struct {
	Format *PresentationDefinitionClaimFormatDesignations `json:"format,omitempty"`
	Frame  *Frame                                         `json:"frame,omitempty"`
	// Id is the id of the presentation definition, it must be unique within the context.
	Id               string             `json:"id"`
	InputDescriptors []*InputDescriptor `json:"input_descriptors"`
	// Name is the name of the presentation definition. Correlates to ID
	Name string `json:"name,omitempty"`
	// Purpose is the purpose of the presentation definition, what is it used for?
	Purpose                *string                  `json:"purpose,omitempty"`
	SubmissionRequirements []*SubmissionRequirement `json:"submission_requirements,omitempty"`
}

// SameSubjectItems
type SameSubjectItems struct {
	Directive string   `json:"directive"`
	FieldId   []string `json:"field_id"`
}

// StatusDirective
type StatusDirective struct {
	Directive string   `json:"directive,omitempty"`
	Type      []string `json:"type,omitempty"`
}

// Statuses
type Statuses struct {
	Active    *StatusDirective `json:"active,omitempty"`
	Revoked   *StatusDirective `json:"revoked,omitempty"`
	Suspended *StatusDirective `json:"suspended,omitempty"`
}

// Field describes a constraints field in a presentation definition's input descriptor.  The predicate feature is not implemented
type Field struct {
	Id             *string  `json:"id,omitempty"`
	Optional       *bool    `json:"optional,omitempty"`
	Path           []string `json:"path"`
	Purpose        *string  `json:"purpose,omitempty"`
	Name           *string  `json:"name,omitempty"`
	IntentToRetain *bool    `json:"intent_to_retain,omitempty"`
	Filter         *Filter  `json:"filter,omitempty"`
}

// Filter is a JSON Schema (without nesting)
type Filter struct {
	// Type is the type of field: string, number, boolean, array, object
	Type string `json:"type"`
	// Const is a constant value to match, currently only strings are supported
	Const *string `json:"const,omitempty"`
	// Enum is a list of values to match
	Enum []string `json:"enum,omitempty"`
	// Pattern is a pattern to match according to ECMA-262, section 21.2.1
	Pattern *string `json:"pattern,omitempty"`
}

// SubmissionRequirement
type SubmissionRequirement struct {
	Count      *int                     `json:"count,omitempty"`
	From       string                   `json:"from,omitempty"`
	FromNested []*SubmissionRequirement `json:"from_nested,omitempty"`
	Max        *int                     `json:"max,omitempty"`
	Min        *int                     `json:"min,omitempty"`
	Name       string                   `json:"name,omitempty"`
	Rule       string                   `json:"rule"`
}
