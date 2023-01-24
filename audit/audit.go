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
	// CryptoDecryptEvent occurs when decrypting data.
	CryptoDecryptEvent = "Decrypt"
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
