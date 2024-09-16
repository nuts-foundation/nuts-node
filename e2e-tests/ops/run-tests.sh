#!/usr/bin/env bash

set -e # make script fail if any of the tests returns a non-zero exit code

echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!! Running test: Key Rotation (DISABLED!) !!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
#pushd key-rotation
#./run-test.sh
#popd

echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!! Running test: Create Subject           !!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
pushd create-subject
./run-test.sh
popd