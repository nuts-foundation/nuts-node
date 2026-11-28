/*
 * Copyright (C) 2026 Nuts community
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

package pe

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// ValidateFieldIDs checks that the field ids of one or more presentation definitions can be given one value
// across a token request. All presentation definitions that are used together in one token request must be
// passed in a single call, since a field id names the same value in all of them.
//
// It enforces the following rules:
//   - a field id is unique within one input descriptor;
//   - for a field id used in more than one input descriptor, filters that declare a type declare the same type,
//     and filters that declare a const declare the same const. Otherwise no credential combination could ever
//     agree on the value. Filters without a type or const (e.g. pattern or enum only) are not compared;
//   - a field id used in more than one input descriptor may not be on an optional field, since an optional
//     field that does not resolve would silently let the descriptors disagree on the value.
//     An optional field whose id is used in only one input descriptor is allowed.
//
// This validation is meant for presentation definitions the node loads from its own configuration
// (policy files, discovery service definitions), where a violation is a configuration error that should stop
// the node from starting. It is deliberately not applied to presentation definitions received from other parties.
//
// All violations are reported (joined), ordered by field id and then by the order of the input descriptors.
func ValidateFieldIDs(definitions ...PresentationDefinition) error {
	// occurrences of each field id, in order of presentation definition, input descriptor and field
	occurrences := make(map[string][]fieldIDOccurrence)
	for definitionIndex, definition := range definitions {
		for descriptorIndex, inputDescriptor := range definition.InputDescriptors {
			if inputDescriptor == nil || inputDescriptor.Constraints == nil {
				continue
			}
			for _, field := range inputDescriptor.Constraints.Fields {
				if field.Id == nil {
					continue
				}
				occurrences[*field.Id] = append(occurrences[*field.Id], fieldIDOccurrence{
					descriptorKey: descriptorKey{definition: definitionIndex, descriptor: descriptorIndex},
					definitionID:  definition.Id,
					descriptorID:  inputDescriptor.Id,
					field:         field,
				})
			}
		}
	}

	ids := make([]string, 0, len(occurrences))
	for id := range occurrences {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var errs []error
	for _, id := range ids {
		errs = append(errs, validateFieldIDOccurrences(id, occurrences[id])...)
	}
	return errors.Join(errs...)
}

// fieldIDOccurrence is a field with an id, together with the input descriptor and presentation definition it is in.
type fieldIDOccurrence struct {
	descriptorKey descriptorKey
	definitionID  string
	descriptorID  string
	field         Field
}

// descriptorKey identifies an input descriptor by its position, since input descriptor ids are only unique
// within one presentation definition.
type descriptorKey struct {
	definition int
	descriptor int
}

func (o fieldIDOccurrence) descriptorName() string {
	return fmt.Sprintf("input descriptor '%s' (presentation definition '%s')", o.descriptorID, o.definitionID)
}

// validateFieldIDOccurrences checks the rules of ValidateFieldIDs for all occurrences of a single field id.
func validateFieldIDOccurrences(id string, occurrences []fieldIDOccurrence) []error {
	var errs []error

	// Group by input descriptor, keeping the order in which descriptors were first seen.
	var descriptors []descriptorKey
	descriptorNames := make(map[descriptorKey]string)
	countPerDescriptor := make(map[descriptorKey]int)
	for _, occurrence := range occurrences {
		if _, seen := descriptorNames[occurrence.descriptorKey]; !seen {
			descriptors = append(descriptors, occurrence.descriptorKey)
			descriptorNames[occurrence.descriptorKey] = occurrence.descriptorName()
		}
		countPerDescriptor[occurrence.descriptorKey]++
	}
	for _, descriptor := range descriptors {
		if countPerDescriptor[descriptor] > 1 {
			errs = append(errs, fmt.Errorf("field id '%s' is used on %d fields of %s, it must be unique within an input descriptor",
				id, countPerDescriptor[descriptor], descriptorNames[descriptor]))
		}
	}
	if len(descriptors) < 2 {
		// The rules below only apply to ids shared between input descriptors.
		return errs
	}
	names := make([]string, len(descriptors))
	for i, descriptor := range descriptors {
		names[i] = descriptorNames[descriptor]
	}
	shared := fmt.Sprintf("field id '%s' is used in %s", id, strings.Join(names, ", "))

	for _, occurrence := range occurrences {
		if occurrence.field.Optional != nil && *occurrence.field.Optional {
			errs = append(errs, fmt.Errorf("%s, but is optional in %s: a field id used in more than one input descriptor may not be optional",
				shared, occurrence.descriptorName()))
		}
	}
	if conflict := conflictingFilterValues(occurrences, func(filter Filter) *string {
		if filter.Type == "" {
			return nil
		}
		return &filter.Type
	}); conflict != "" {
		errs = append(errs, fmt.Errorf("%s, with conflicting filter types: %s", shared, conflict))
	}
	if conflict := conflictingFilterValues(occurrences, func(filter Filter) *string {
		return filter.Const
	}); conflict != "" {
		errs = append(errs, fmt.Errorf("%s, with conflicting filter consts: %s", shared, conflict))
	}
	return errs
}

// conflictingFilterValues returns a description of the values the given filter property has on the occurrences,
// if not all occurrences that declare the property declare the same value. It returns an empty string otherwise.
func conflictingFilterValues(occurrences []fieldIDOccurrence, property func(filter Filter) *string) string {
	var values []string
	var descriptions []string
	for _, occurrence := range occurrences {
		if occurrence.field.Filter == nil {
			continue
		}
		value := property(*occurrence.field.Filter)
		if value == nil {
			continue
		}
		if !slices.Contains(values, *value) {
			values = append(values, *value)
		}
		descriptions = append(descriptions, fmt.Sprintf("'%s' in %s", *value, occurrence.descriptorName()))
	}
	if len(values) < 2 {
		return ""
	}
	return strings.Join(descriptions, ", ")
}
