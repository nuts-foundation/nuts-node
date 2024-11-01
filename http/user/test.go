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

package user

import (
	"context"
	"time"
)

func CreateTestSession(ctx context.Context, subjectID string) (context.Context, *Session) {
	session, _ := createUserSession(subjectID, time.Hour)
	session.Save = func() error {
		return nil
	}
	return context.WithValue(ctx, userSessionContextKey{}, session), session
}
