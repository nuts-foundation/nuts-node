#!/usr/bin/env bash

set -e # make script fail if any of the tests returns a non-zero exit code

echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!! Running test: Redis            !!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
pushd redis
./run-test.sh
popd

echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!! Running test: Backup/Restore   !!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
pushd backup-restore
./prepare.sh
./run-test.sh
popd

echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!! Running test: Vault crypto storage !!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
pushd vault
./run-test.sh
popd