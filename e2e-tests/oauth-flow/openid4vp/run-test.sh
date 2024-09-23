#!/usr/bin/env bash
set -e
./do-test.sh didweb-user
# skip test, root did:web is not supported and test is broken
# ./do-test.sh didweb-root