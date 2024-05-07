#!/usr/bin/env bash
function createDB {
  $1 exec db /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P 'MyStrong(!)Password' -Q "CREATE DATABASE node_a; CREATE DATABASE node_b;"
}