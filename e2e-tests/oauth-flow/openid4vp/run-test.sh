#!/usr/bin/env bash
set -e
./do-test.sh didweb-user
# skip test, root did:web is not supported and test is broken
# see https://github.com/nuts-foundation/nuts-node/issues/3299
# ./do-test.sh didweb-root