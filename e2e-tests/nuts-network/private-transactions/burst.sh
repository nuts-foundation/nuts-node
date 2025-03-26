#!/usr/bin/env bash

set -e

for i in {1..200}; do
  echo $REQUESTA | curl -X POST -s --data-binary @- http://localhost:28081/internal/auth/v1/request-access-token -H "Content-Type:application/json" > /dev/null &
  echo $REQUESTB | curl -X POST -s --data-binary @- http://localhost:18081/internal/auth/v1/request-access-token -H "Content-Type:application/json" > /dev/null &
done