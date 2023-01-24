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
	log "github.com/sirupsen/logrus"
)

const (
	// CryptoNewKeyEvent occurs when creating a new key.
	CryptoNewKeyEvent = "CreateNewKey"
	// CryptoSignJWTEvent occurs when signing a JWT.
	CryptoSignJWTEvent = "SignJWT"
	// CryptoSignJWSEvent occurs when signing a JWS.
	CryptoSignJWSEvent = "SignJWS"
)

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

// Log logs the given message as an audit event. The context must contain audit information.
func Log(ctx context.Context, logger *log.Entry, eventName string) *log.Entry {
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

	return logger.WithField("log", "audit").
		WithField("actor", info.Actor).
		WithField("operation", info.Operation).
		WithField("event", eventName)
}
