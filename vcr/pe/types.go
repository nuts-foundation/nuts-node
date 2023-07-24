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

package pe

// PresentationSubmission
type PresentationSubmission struct {
	Id            string                         `json:"id"`
	DefinitionId  string                         `json:"definition_id"`
	DescriptorMap []InputDescriptorMappingObject `json:"descriptor_map"`
}

// InputDescriptorMappingObject
type InputDescriptorMappingObject struct {
	Id     string `json:"id"`
	Path   string `json:"path"`
	Format string `json:"format"`
}
