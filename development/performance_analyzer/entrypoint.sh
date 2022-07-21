#!/bin/sh
set -e

# can't start a service without checking status first...
echo "Service 'All': Status"
rc-status -a

echo "Service 'node-exporter': Starting ..."
rc-service node-exporter start

# this script should be set as the docker ENTRYPOINT and provided CMD will be executed below
echo "Command: '$@'"
exec $@