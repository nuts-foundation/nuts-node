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
	"go.uber.org/mock/gomock"
	"testing"
)

func TestLandingPage_Routes(t *testing.T) {
	ctrl := gomock.NewController(t)

	e := NewMockEchoRouter(ctrl)
	e.EXPECT().Add("GET", "/", gomock.Any())
	LandingPage{}.Routes(e)
}
