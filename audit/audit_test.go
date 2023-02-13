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

package audit

import (
	"context"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLog(t *testing.T) {
	t.Run("it adds the audit fields to the logger", func(t *testing.T) {
		ctx := TestContext()

		actual := Log(ctx, logrus.NewEntry(logrus.StandardLogger()), "test")

		assert.Equal(t, "test", actual.Data["event"])
		assert.Equal(t, TestActor, actual.Data["actor"])
	})
	t.Run("it panics when no actor is set", func(t *testing.T) {
		assert.Panics(t, func() {
			Log(context.Background(), logrus.NewEntry(logrus.StandardLogger()), "test")
		})
	})
	t.Run("it panics when no event name is set", func(t *testing.T) {
		assert.Panics(t, func() {
			Log(TestContext(), logrus.NewEntry(logrus.StandardLogger()), "")
		})
	})
}
