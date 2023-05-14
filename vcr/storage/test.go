package storage

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var localDID = did.MustParseDID("did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW")
var otherDID = did.MustParseDID("did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY")

// startDatabase creates a PostgreSQL container and returns a database connection to it.
// See https://dev.to/remast/go-integration-tests-using-testcontainers-9o5
func startDatabase() (testcontainers.Container, *sql.DB, error) {
	ctx := context.Background()
	containerReq := testcontainers.ContainerRequest{
		Image:        "postgres:latest",
		ExposedPorts: []string{"5432/tcp"},
		WaitingFor:   wait.ForListeningPort("5432/tcp"),
		Env: map[string]string{
			"POSTGRES_DB":       "test",
			"POSTGRES_PASSWORD": "postgres",
			"POSTGRES_USER":     "postgres",
		},
	}

	// 2. Start PostgreSQL container
	container, _ := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: containerReq,
			Started:          true,
		})

	host, _ := container.Host(ctx)
	port, _ := container.MappedPort(ctx, "5432")

	dbURI := fmt.Sprintf("postgres://postgres:postgres@%v:%v/test?sslmode=disable", host, port.Port())
	println("Connection string: " + dbURI)
	db, err := sql.Open("postgres", dbURI)
	if err != nil {
		return nil, nil, err
	}
	return container, db, nil
}
