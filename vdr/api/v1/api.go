/*
 * Nuts registry
 * Copyright (C) 2020. Nuts community
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

import (
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/vdr"
)

// ApiWrapper is needed to connect the implementation to the echo ServiceWrapper
type ApiWrapper struct {
	R vdr.Store
}

func (a ApiWrapper) SearchDID(ctx echo.Context, params SearchDIDParams) error {
	panic("implement me")
}

func (a ApiWrapper) CreateDID(ctx echo.Context) error {
	panic("implement me")
}

func (a ApiWrapper) GetDID(ctx echo.Context, didOrTag string) error {
	panic("implement me")
}

func (a ApiWrapper) UpdateDID(ctx echo.Context, didOrTag string) error {
	panic("implement me")
}

func (a ApiWrapper) UpdateDIDTags(ctx echo.Context, didOrTag string) error {
	panic("implement me")
}

