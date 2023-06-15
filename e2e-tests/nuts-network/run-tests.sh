#!/usr/bin/env bash

set -e # make script fail if any of the tests returns a non-zero exit code


echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!! Running test: Direct WAN       !!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
pushd direct-wan
./run-test.sh
popd

echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!! Running test: Private TXs      !!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
pushd private-transactions
./prepare.sh
./run-test.sh
popd

pushd ssl-offloading
./run-tests.sh
popd

echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!! Running test: SSL-Pass-Through !!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
pushd ssl-pass-through
./run-test.sh
popd

echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!! Running test: Gossip           !!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
pushd gossip
./run-test.sh
popd

echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!! Running test: Gossip-Overflow  !!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
pushd gossip-overflow
./run-test.sh
popd
