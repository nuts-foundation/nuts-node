#!/usr/bin/env bash
set -e

echo "===================================="
echo "Testing denylist with default settings"
echo "===================================="
pushd defaults
./run-test.sh
popd

echo "===================================="
echo "Testing denylist with raw github URL"
echo "===================================="
pushd github
./run-test.sh
popd
