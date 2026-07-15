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

// Package pe implements Presentation Exchange (PEX): matching the Verifiable Credentials in a
// wallet against a Presentation Definition, and building the Presentation Submission that
// presents the chosen ones. Select is the single matching engine; Match and the submission
// builder are layered on top of it.
//
// # Vocabulary
//
// The documentation in this package uses these terms consistently:
//
//   - Presentation definition (PD): the verifier's description of the credentials it wants: a
//     set of input descriptors, plus optional submission requirements. In this system the PD is
//     the data contract: only fields the PD declares are mapped to token introspection, so a
//     field the PD does not declare plays no role in credential selection either. A filter that
//     admits several values, such as an issuer pattern, is a deliberate equivalence declaration
//     by the PD author.
//   - Input descriptor: one slot of the PD, filled by at most one credential. Its constraint
//     fields (JSONPaths with optional filters) and format designations decide which credentials
//     fit the slot.
//   - Field id / binding name: the optional id on a constraint field. A field id names the
//     resolved value in two directions: outward, as the key under which the value appears in
//     token introspection and is addressed by the credential_selection parameter; and inward,
//     as a binding name, meaning that wherever the same id appears in one selection, the
//     resolved values must agree.
//   - Binding: an id-to-value pair the selection has committed to. Bindings accumulate while
//     the engine fills descriptors, and constrain every later choice. A credential's resolved
//     id-to-value pairs for a descriptor are its binding tuple.
//   - Initial bindings: bindings supplied before the search starts (WithInitialBindings): the
//     caller's credential_selection, or values captured from an earlier presentation in a
//     two-VP flow. A descriptor is caller-bound when one of its field ids appears in the
//     initial bindings. A caller-bound descriptor must resolve the bound field to the bound
//     value (an unresolved optional field does not qualify) and must resolve to exactly one
//     interchangeable set of credentials.
//   - Eligible credential: a credential that satisfies one input descriptor on its own,
//     constraints and formats, before any cross-descriptor consistency is considered.
//   - Interchangeable credentials: eligible credentials with identical binding tuples. By the
//     data-contract principle nothing the PD declares tells them apart, and no
//     credential_selection key could, so the engine treats them as a single choice and uses the
//     first in candidate order. Interchangeable credentials whose credentialSubjects
//     nevertheless differ are flagged in the MatchReport (DivergingAlternatives).
//   - Assignment: a choice of credential, or none, per input descriptor. The engine searches
//     for a complete assignment with consistent bindings. The assignment it settles on, also on
//     failure, is the decisive assignment: it is what Result reports and what the MatchReport
//     explains dismissals against.
//   - Optional descriptor: a descriptor the submission requirements allow to go unfilled, for
//     example a member of a pick group. Optionality governs whether zero matches is acceptable;
//     it never relaxes the multiplicity or consistency rules (zero-vs-some, never one-vs-many).
//   - Selection strategy: what to do when more than one materially different complete
//     assignment exists. FirstMatch, the default, takes the first found; Strict reports
//     ambiguity as ErrMultipleCredentials, naming the descriptors to disambiguate with
//     credential_selection keys.
//   - Selection trace: the opt-in diagnostic (WithSelectionTrace) that explains, per descriptor
//     and candidate, why each credential was or wasn't used. See MatchReport.
//
// These concepts originate as the numbered policies of the design in
// https://github.com/nuts-foundation/nuts-node/issues/4253.
package pe
