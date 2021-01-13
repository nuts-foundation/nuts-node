/*
 * Nuts go core
 * Copyright (C) 2019 Nuts community
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

package core

// NutsOID is the officially registered OID: http://oid-info.com/get/1.3.6.1.4.1.54851
const NutsOID = "1.3.6.1.4.1.54851"

// NutsConsentClassesOID is the sub-OID used for consent classification
const NutsConsentClassesOID = NutsOID + ".1"

// NutsVendorOID is the sub-OID used for vendor identifiers
const NutsVendorOID = NutsOID + ".4"