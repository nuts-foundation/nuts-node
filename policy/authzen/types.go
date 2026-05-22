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

package authzen

// EvaluationsRequest is the batch request for the AuthZen Access Evaluations API (POST /access/v1/evaluations).
// Top-level fields are shared defaults; individual evaluations override only the resource.
type EvaluationsRequest struct {
	Subject     Subject           `json:"subject"`
	Action      Action            `json:"action"`
	Context     EvaluationContext `json:"context"`
	Evaluations []Evaluation      `json:"evaluations"`
}

// Evaluation is a single evaluation within a batch request, overriding the resource.
type Evaluation struct {
	Resource Resource `json:"resource"`
}

// Subject identifies the entity requesting access.
type Subject struct {
	Type       string            `json:"type"`
	ID         string            `json:"id"`
	Properties SubjectProperties `json:"properties"`
}

// SubjectProperties contains claims extracted from validated VCs, grouped by role.
type SubjectProperties struct {
	Client       map[string]any `json:"client,omitempty"`
	Organization map[string]any `json:"organization,omitempty"`
	User         map[string]any `json:"user,omitempty"`
}

// Action describes the operation being requested.
type Action struct {
	Name string `json:"name"`
}

// Resource identifies the resource being accessed.
type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// EvaluationContext provides additional context for policy routing.
type EvaluationContext struct {
	Policy string `json:"policy"`
}

// EvaluationsResponse is the batch response from the AuthZen Access Evaluations API.
type EvaluationsResponse struct {
	Evaluations []EvaluationResult `json:"evaluations"`
}

// EvaluationResult contains the decision for a single evaluation.
type EvaluationResult struct {
	Decision bool                     `json:"decision"`
	Context  *EvaluationResultContext `json:"context,omitempty"`
}

// EvaluationResultContext contains supplementary information about an evaluation decision.
type EvaluationResultContext struct {
	Reason string `json:"reason,omitempty"`
}
