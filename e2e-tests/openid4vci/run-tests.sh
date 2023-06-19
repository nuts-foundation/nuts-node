#!/usr/bin/env bash

set -e # make script fail if any of the tests returns a non-zero exit code


echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!! Running test: Issuer Initiated !!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
pushd issuer-initiated
./run-test.sh
popd
