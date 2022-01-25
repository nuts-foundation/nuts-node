/*
 * Copyright (C) 2021 Nuts community
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

package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		panic(fmt.Sprintf("Missing/too many args: %v", os.Args))
	}

	param := os.Args[1]
	switch param {
	case "docs":
		generateDocs()
	case "copyright":
		fixCopyright()
	default:
		panic("Unknown command " + param)
	}
}
