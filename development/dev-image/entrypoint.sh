#!/bin/bash

source ~/.bashrc

NUTS_TUNNEL_PATH="./config/nuts-devtunnel"
# mkdir if not mounted
mkdir -p $NUTS_TUNNEL_PATH

# login with github user
devtunnel user login -d -g

# clear log without error if does not exist
rm -f ${NUTS_TUNNEL_PATH}/tunnel.log

# read from ${NUTS_TUNNEL_PATH}/tunnel.id
# if it does not exist, create a new tunnel
if [ ! -f ${NUTS_TUNNEL_PATH}/tunnel.id ]; then
  # create persistent tunnel. We could set our own TUNNEL_ID, but a random one seems more fault tolerant.
  # calling "devtunnel host" without TUNNEL_ID creates a temporary tunnel, so we need to create a persistent tunnel first.
  # https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/faq#how-can-i-create-a-persistent-tunnel
  devtunnel create -a >> ${NUTS_TUNNEL_PATH}/tunnel.log 2>&1
  # add port 8080 to most recent tunnel. (can't be done in a single call unfortunately)
  devtunnel port create -p 8080 >> ${NUTS_TUNNEL_PATH}/tunnel.log 2>&1
  # save the TUNNEL_ID
  grep "Tunnel ID" ${NUTS_TUNNEL_PATH}/tunnel.log | head -1 | awk '{print $4}' > ${NUTS_TUNNEL_PATH}/tunnel.id
fi

# Execute the devtunnel host command and write the output to a log file
devtunnel host $(cat ${NUTS_TUNNEL_PATH}/tunnel.id) >> ${NUTS_TUNNEL_PATH}/tunnel.log 2>&1 &
# safe the pid for later
echo $! > ${NUTS_TUNNEL_PATH}/tunnel.pid

# Try 30 times to read the tunnel URL from the log file.
# The format is "your url is:" followed by the URL.
echo "Waiting for devurl URL (time-out in 10s)..."
for i in $(seq 1 10); do
  TUNNEL_URL=$(grep "Connect via browser:" ${NUTS_TUNNEL_PATH}/tunnel.log | awk '{print $5}')
  TUNNEL_ID=$(grep "Ready to accept connections for tunnel:" ${NUTS_TUNNEL_PATH}/tunnel.log | awk '{print $7}')
  if [ -n "$TUNNEL_URL" ]; then
    break
  fi
  sleep 1
done

# Check whether we retrieved the URL and if not, exit with an error.
if [ -z "$TUNNEL_URL" ]; then
  echo "Failed to retrieve the devtunnel URL"
  cat ${NUTS_TUNNEL_PATH}/tunnel.log
  exit 1
fi

# store the tunnel id in ${NUTS_TUNNEL_PATH}/tunnel.id
echo $TUNNEL_ID > ${NUTS_TUNNEL_PATH}/tunnel.id
echo Your Nuts node URL is: ${TUNNEL_URL}

NUTS_URL="${TUNNEL_URL}" NUTS_STRICTMODE=false NUTS_AUTH_CONTRACTVALIDATORS=dummy NUTS_HTTP_INTERNAL_ADDRESS=:8081 exec /usr/bin/nuts server

# Kill the localtunnel process when the container stops
kill $(cat ${NUTS_TUNNEL_PATH}/tunnel.pid)
