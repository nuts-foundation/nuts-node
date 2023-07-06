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
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"strings"
	"testing"
)

const TestActor = "test-actor"

func TestContext() context.Context {
	return Context(context.Background(), TestActor, "TestModule", "TestOperation")
}

type contextWithAuditInfoMatcher struct {
}

func (e contextWithAuditInfoMatcher) Matches(x interface{}) bool {
	ctx, ok := x.(context.Context)
	if !ok {
		return false
	}
	_, ok = ctx.Value(auditContextKey{}).(Info)
	return ok
}

func (e contextWithAuditInfoMatcher) String() string {
	return "context contains audit info"
}

func ContextWithAuditInfo() gomock.Matcher {
	return contextWithAuditInfoMatcher{}
}

func AssertAuditInfo(t *testing.T, ctx echo.Context, actor, module, operation string) {
	t.Helper()
	info := InfoFromContext(ctx.Request().Context())
	require.NotNil(t, info)
	assert.Equal(t, actor, info.Actor)
	assert.Equal(t, module+"."+operation, info.Operation)
}

type CapturedLog struct {
	hook *test.Hook
}

func (c *CapturedLog) Contains(t *testing.T, eventName string) bool {
	t.Helper()
	for _, entry := range c.hook.AllEntries() {
		if entry.Data["event"] == eventName {
			return true
		}
	}
	return false
}

func (c *CapturedLog) AssertContains(t *testing.T, module string, event string, actor string, message string) {
	t.Helper()
	for _, entry := range c.hook.AllEntries() {
		if entry.Data["module"] == module &&
			entry.Data["event"] == event &&
			entry.Data["actor"] == actor &&
			entry.Message == message {
			formatted, err := entry.Logger.Formatter.Format(entry)
			require.NoError(t, err)
			// Assert that the log entry is logged on "audit" level (since that's achieved rather hacky)
			if !strings.Contains(string(formatted), "level=audit") && !strings.Contains(string(formatted), "AUDIT") {
				t.Error("Audit log entry is not logged on 'audit' level")
			}
			return
		}
	}
	// If failed, collect log entries for error message
	var entries []string
	for _, entry := range c.hook.AllEntries() {
		msg, _ := (&logrus.TextFormatter{}).Format(entry)
		entries = append(entries, string(msg))
	}
	t.Errorf("Audit log doesn't contain expected entry with"+
		"  expected: module=%s, event=%s, description=%s, actor=%s\n"+
		"  found: %v", module, event, message, actor, entries)
}

func CaptureLogs(t *testing.T) *CapturedLog {
	// Reset the hooks to their original state when the test ends
	oldHooks := auditLogger().Hooks
	t.Cleanup(func() {
		auditLogger().ReplaceHooks(oldHooks)
	})

	hook := &test.Hook{}
	auditLogger().AddHook(hook)
	return &CapturedLog{hook: hook}
}
