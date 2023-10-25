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

// PresentationDefinitionClaimFormatDesignations (replaces generated one)
type PresentationDefinitionClaimFormatDesignations map[string]map[string][]string

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

// SubmissionRequirement
type SubmissionRequirement struct {
}
