#!/usr/bin/env bash
set -e # make script fail if any of the tests returns a non-zero exit code
./do-test.sh postgres
./do-test.sh mysql
./do-test.sh sqlite
./do-test.sh sqlserver