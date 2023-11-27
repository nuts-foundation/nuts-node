#!/usr/bin/env bash

set -e # make script fail if any of the tests returns a non-zero exit code

echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!! Running test: OAuth flow (rfc002) !!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
pushd rfc002
./run-test.sh
popd

echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!! Running test: OAuth flow (OpenID4VP-s2s) !!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
pushd openid4vp
./run-test.sh
popd
