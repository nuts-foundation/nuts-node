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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"strings"
	"sync"
)

const (
	// CryptoNewKeyEvent occurs when creating a new key.
	CryptoNewKeyEvent = "CreateNewKey"
	// CryptoSignJWTEvent occurs when signing a JWT.
	CryptoSignJWTEvent = "SignJWT"
	// CryptoSignJWSEvent occurs when signing a JWS.
	CryptoSignJWSEvent = "SignJWS"

	// AccessDeniedEvent occurs when access to a protected API endpoint was granted
	AccessGrantedEvent = "AccessGranted"
	// AccessDeniedEvent occurs when access to a protected API endpoint was denied
	AccessDeniedEvent = "AccessDenied"
	// AccessKeyRegisteredEvent occurs when an authorized key is registered for future authorization events
	AccessKeyRegisteredEvent = "AccessKeyRegistered"

	// CryptoEncryptJWEEvent occurs when encryping a JWE
	CryptoEncryptJWEEvent = "EncryptJWE"
	// CryptoDecryptJWEEvent occurs when decryping a JWE
	CryptoDecryptJWEEvent = "DecryptJWE"
)

const auditLogLevel = "audit"

// auditLoggerInstance is the logger for auditing. Do not use directly, call auditLogger() instead.
var auditLoggerInstance *logrus.Logger
var initAuditLoggerOnce = &sync.Once{}

// auditLogger returns the initialized logger instance intended for audit logging.
func auditLogger() *logrus.Logger {
	initAuditLoggerOnce.Do(func() {
		// Create new logger with custom Formatter, which makes sures the log level is always "audit".
		// Also override the level for this logger, to make sure it is not influenced by a lower log verbosity.
		// It contains somewhat hacky string replacement, since logrus doesn't support custom log levels
		// and will probably never do so (since it's in maintenance mode).
		// Should be solved by migrating to a different logging library, which does support custom log levels.
		// Alternative solution would be to extend the audit feature to always write to another audit sink (e.g. different log file or database).
		// Then the audit logs in the application log don't matter that much anymore, and they can be logged on e.g., INFO.
		auditFormatter, err := newAuditFormatter(logrus.StandardLogger().Formatter)
		if err != nil {
			panic(fmt.Sprintf("audit: failed to create audit logger: %v", err))
		}
		auditLoggerInstance = logrus.New()
		auditLoggerInstance.SetFormatter(auditFormatter)
		auditLoggerInstance.SetLevel(logrus.InfoLevel)
	})
	return auditLoggerInstance
}

// Info provides contextual information for auditable events.
type Info struct {
	// Actor is the user or service that performed the operation.
	Actor string
	// Operation is the name of the operation that was performed.
	Operation string
}

type auditContextKey struct{}

// Context returns a child context of the given parent context, enriched with the auditable actor and performed operation.
func Context(parent context.Context, actor, module, operationName string) context.Context {
	return context.WithValue(parent, auditContextKey{}, Info{
		Actor:     actor,
		Operation: module + "." + operationName,
	})
}

// InfoFromContext extracts the audit info from the given context.
func InfoFromContext(ctx context.Context) *Info {
	actor, ok := ctx.Value(auditContextKey{}).(Info)
	if ok {
		return &actor
	}
	return nil
}

// newAuditFormatter wraps the given logrus.Formatter in a new Formatter that makes sure the log level is always "audit".
func newAuditFormatter(formatter logrus.Formatter) (logrus.Formatter, error) {
	switch f := formatter.(type) {
	case *logrus.JSONFormatter:
		return jsonAuditFormatter{formatter: f}, nil
	case *logrus.TextFormatter:
		return textAuditFormatter{formatter: f}, nil
	default:
		return nil, fmt.Errorf("audit: unsupported log formatter: %T", f)
	}
}

type jsonAuditFormatter struct {
	formatter *logrus.JSONFormatter
}

type textAuditFormatter struct {
	formatter *logrus.TextFormatter
}

func (a textAuditFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// Make log level predictable for easier replacement later
	// (then level color for colored output is known beforehand, which is 36 for info)
	// See sirupsen/logrus@v1.9.0/text_formatter.go:19
	entry.Level = logrus.InfoLevel

	formattedEntry, err := a.formatter.Format(entry)
	if err != nil {
		return nil, err
	}
	coloredPrefix := []byte("\x1b[36mINFO")
	if bytes.HasPrefix(formattedEntry, coloredPrefix) {
		// Colored output
		coloredResult := append(formattedEntry[0:len(coloredPrefix)-4], []byte(strings.ToUpper(auditLogLevel))...)
		coloredResult = append(coloredResult, formattedEntry[len(coloredPrefix)+4:]...)
		return coloredResult, nil
	}
	// Non-colored output
	return bytes.Replace(formattedEntry, []byte("level="+entry.Level.String()), []byte("level="+auditLogLevel), 1), nil
}

func (a jsonAuditFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	formattedEntry, err := a.formatter.Format(entry)
	if err != nil {
		return nil, err
	}
	var logAsJSON map[string]interface{}
	err = json.Unmarshal(formattedEntry, &logAsJSON)
	if err != nil {
		return nil, fmt.Errorf("audit: failed to unmarshal log entry: %w", err)
	}
	logAsJSON["level"] = auditLogLevel
	return json.Marshal(logAsJSON)
}

// Log logs the given message as an audit event. The context must contain audit information.
func Log(ctx context.Context, logger *logrus.Entry, eventName string) *logrus.Entry {
	info := InfoFromContext(ctx)
	if info == nil {
		panic("audit: no audit info in context")
	}
	if info.Actor == "" {
		panic("audit: actor is empty")
	}
	if info.Operation == "" {
		panic("audit: operation is empty")
	}
	if eventName == "" {
		panic("audit: eventName is empty")
	}

	return auditLogger().WithFields(logger.Data).
		WithField("actor", info.Actor).
		WithField("operation", info.Operation).
		WithField("event", eventName)
}
