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

package v1

//// lists maps a list name (last path part of use case endpoint) to the list ID
//lists map[string]string
//// name is derived from endpoint: it's the last path part of the definition endpoint
//// It is used to route HTTP GET requests to the correct list.
//pathParts := strings.Split(definition.Endpoint, "/")
//name := pathParts[len(pathParts)-1]
//if name == "" {
//return nil, fmt.Errorf("can't derive list name from definition endpoint: %s", definition.Endpoint)
//}
