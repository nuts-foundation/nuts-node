# SQL database support

Start a Docker container with a Postgres database:

```bash

    docker run --name postgres -e POSTGRES_PASSWORD=postgres -p "5432:5432" postgres 