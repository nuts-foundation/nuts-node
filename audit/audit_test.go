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
	"strings"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func Test_auditLogger(t *testing.T) {
	t.Run("invalid formatter", func(t *testing.T) {
		initAuditLoggerOnce = &sync.Once{}
		logrus.StandardLogger().SetFormatter(&textAuditFormatter{})
		assert.Panics(t, func() {
			auditLogger()
		})
	})
}

func Test_newAuditFormatter(t *testing.T) {
	t.Run("unsupported", func(t *testing.T) {
		f, err := newAuditFormatter(&textAuditFormatter{})

		assert.Nil(t, f)
		assert.EqualError(t, err, "audit: unsupported log formatter: *audit.textAuditFormatter")
	})
}

func Test_textAuditFormatter(t *testing.T) {
	t.Run("colored", func(t *testing.T) {
		textFormatter := &logrus.TextFormatter{}
		textFormatter.ForceColors = true
		f, err := newAuditFormatter(textFormatter)
		require.NoError(t, err)

		actual, err := f.Format(logEntry())

		require.NoError(t, err)
		assert.Contains(t, string(actual), "Hello, World!")
		assert.NotContains(t, string(actual), "INFO")
		assert.True(t, strings.HasPrefix(string(actual), "\x1b[36mAUDIT["))
	})
	t.Run("non-colored", func(t *testing.T) {
		f, err := newAuditFormatter(&logrus.TextFormatter{})
		require.NoError(t, err)

		actual, err := f.Format(logEntry())

		require.NoError(t, err)
		assert.Equal(t, `time="0001-01-01T00:00:00Z" level=audit msg="Hello, World!" foo=bar`+"\n", string(actual))
	})
}

func Test_jsonAuditFormatter(t *testing.T) {
	f, err := newAuditFormatter(&logrus.JSONFormatter{})
	require.NoError(t, err)

	actual, err := f.Format(logEntry())

	require.NoError(t, err)
	assert.Equal(t, string(actual), `{"foo":"bar","level":"audit","msg":"Hello, World!","time":"0001-01-01T00:00:00Z"}`)
}

func logEntry() *logrus.Entry {
	e := logrus.StandardLogger().WithField("foo", "bar")
	e.Level = logrus.InfoLevel
	e.Message = "Hello, World!"
	return e
}
