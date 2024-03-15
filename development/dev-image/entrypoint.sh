#!/bin/bash

source ~/.bashrc
# mkdir if not mounted
mkdir -p /devtunnel

# login with github user
devtunnel user login -d -g

# read from /devtunnel/tunnelid
# if it exists add it to the end of the devtunnel host command
devtunnel_host_command="devtunnel host -p 8080 -a"
if [ -f /devtunnel/tunnel.id ]; then
  devtunnel_host_command="devtunnel host $(cat /devtunnel/tunnel.id)"
fi

# Execute the devtunnel host command and write the output to a log file
${devtunnel_host_command} > /devtunnel/tunnel.log 2>&1 &
# safe the pid for later
echo $! > /devtunnel/tunnel.pid

# Try 30 times to read the tunnel URL from the log file.
# The format is "your url is:" followed by the URL.
echo "Waiting for devurl URL (time-out in 10s)..."
for i in $(seq 1 10); do
  TUNNEL_URL=$(grep "Connect via browser:" /devtunnel/tunnel.log | awk '{print $5}')
  TUNNEL_ID=$(grep "Ready to accept connections for tunnel:" /devtunnel/tunnel.log | awk '{print $7}')
  if [ -n "$TUNNEL_URL" ]; then
    break
  fi
  sleep 1
done

# Check whether we retrieved the URL and if not, exit with an error.
if [ -z "$TUNNEL_URL" ]; then
  echo "Failed to retrieve the devtunnel URL"
  cat /devtunnel/tunnel.log
  exit 1
fi

# store the tunnel id in /devtunnel/tunnel.id
echo $TUNNEL_ID > /devtunnel/tunnel.id
echo Your Nuts node URL is: ${TUNNEL_URL}

NUTS_URL="${TUNNEL_URL}" NUTS_STRICTMODE=false NUTS_AUTH_CONTRACTVALIDATORS=dummy NUTS_HTTP_INTERNAL_ADDRESS=:8081 exec /usr/bin/nuts server

# Kill the localtunnel process when the container stops
kill $(cat /devtunnel/tunnel.pid)
