#!/usr/bin/env bash
function createDB {
  $1 exec db psql -U postgres -c "CREATE DATABASE node_a"
  $1 exec db psql -U postgres -c "CREATE DATABASE node_b"
}
