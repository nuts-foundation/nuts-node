package audit

import (
	"context"
	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"testing"
)

const TestActor = "test-actor"

func TestContext() context.Context {
	return Context(context.Background(), func() Info {
		return Info{
			Actor:     TestActor,
			Operation: "TestOperation",
		}
	})
}

type contextWithAuditInfoMatcher struct {
}

func (e contextWithAuditInfoMatcher) Matches(x interface{}) bool {
	ctx, ok := x.(context.Context)
	if !ok {
		return false
	}
	_, ok = ctx.Value(auditInfoContextKey).(func() Info)
	return ok
}

func (e contextWithAuditInfoMatcher) String() string {
	return "context contains audit info"
}

func ContextWithAuditInfo() gomock.Matcher {
	return contextWithAuditInfoMatcher{}
}

type CapturedLog struct {
	hook *test.Hook
}

func (c *CapturedLog) AssertContains(t *testing.T, module string, event string, actor string, message string) {
	for _, entry := range c.hook.AllEntries() {
		if entry.Data["log"] == "audit" &&
			entry.Data["module"] == module &&
			entry.Data["event"] == event &&
			entry.Data["actor"] == actor &&
			entry.Message == message {
			return
		}
	}
	// If failed, collect log entries for error message
	var entries []string
	for _, entry := range c.hook.AllEntries() {
		if entry.Data["log"] == "audit" {
			msg, _ := (&logrus.TextFormatter{}).Format(entry)
			entries = append(entries, string(msg))
		}
	}
	t.Errorf("Audit log doesn't contain expected entry with"+
		"  expected: module=%s, event=%s, description=%s, actor=%s\n"+
		"  found: %v", module, event, message, actor, entries)
}

func CaptureLogs(t *testing.T) *CapturedLog {
	logger := logrus.StandardLogger()
	// Reset the hooks to their original state when the test ends
	oldHooks := logger.Hooks
	t.Cleanup(func() {
		logger.ReplaceHooks(oldHooks)
	})

	hook := &test.Hook{}
	logger.AddHook(hook)
	return &CapturedLog{hook: hook}
}
