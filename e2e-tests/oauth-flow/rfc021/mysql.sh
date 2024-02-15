#!/usr/bin/env bash
function createDB {
  $1 exec db mysql -u root --password=root -e 'CREATE DATABASE node_a; CREATE DATABASE node_b;'
}
