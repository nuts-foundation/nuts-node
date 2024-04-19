/*
 * Copyright (C) 2024 Nuts community
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

package assets

import (
	"embed"
	"html/template"
)

//go:embed *.html
var assets embed.FS

// ErrorTemplate is the template used to render error pages.
var ErrorTemplate *template.Template

func init() {
	templates := template.Must(template.ParseFS(assets, "*.html"))
	ErrorTemplate = templates.Lookup("error.html")
}
