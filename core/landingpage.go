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

package core

import (
	"embed"
	"github.com/labstack/echo/v4"
	"net/http"
)

//go:embed landingpage.html
var landingPageResource embed.FS

// LandingPage is a Routable that exposes a landing page at the node's HTTP root (`/`).
type LandingPage struct{}

// Routes registers the landing page on the given EchoRouter.
func (l LandingPage) Routes(router EchoRouter) {
	router.Add("GET", "/", func(context echo.Context) error {
		contents, err := l.load()
		if err != nil {
			return err
		}
		return context.HTML(http.StatusOK, contents)
	})
}

func (l LandingPage) load() (string, error) {
	contents, err := landingPageResource.ReadFile("landingpage.html")
	if err != nil {
		return "", err
	}
	return string(contents), nil
}
