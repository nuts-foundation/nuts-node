#!/bin/sh

# Try to read the subdomain from localtunnel.cfg
SUBDOMAIN=$(cat /localtunnel.cfg 2>/dev/null)

# Run lt to create the local tunnel with --port 1323 as background process.
# It writes the URL to stdout which we need to extract and feed to the nuts command
lt --port 1323 --subdomain="${SUBDOMAIN}" > /localtunnel.log 2>&1 &

# Try 30 times to read the tunnel URL from the log file.
# The format is "your url is:" followed by the URL.
echo "Waiting for localtunnel URL (time-out in 30s)..."
for i in $(seq 1 30); do
  TUNNEL_URL=$(grep "your url is:" /localtunnel.log | awk '{print $4}')
  if [ -n "$TUNNEL_URL" ]; then
    break
  fi
  sleep 1
done
# Check whether we retrieved the URL and if not, exit with an error.
if [ -z "$TUNNEL_URL" ]; then
  echo "Failed to retrieve the localtunnel URL"
  cat /localtunnel.log
  exit 1
fi
# Extract subdomain (TUNNEL_URL after https:// up to the first .)
SUBDOMAIN=$(echo $TUNNEL_URL | awk -F/ '{print $3}' | awk -F. '{print $1}')
# Store subdomain in localtunnel.cfg so that the container retains its subdomain after restart
echo "${SUBDOMAIN}" > /localtunnel.cfg

echo Your Nuts node URL is: ${TUNNEL_URL}
NUTS_URL="${TUNNEL_URL}" NUTS_STRICTMODE=false NUTS_AUTH_CONTRACTVALIDATORS=dummy exec /usr/bin/nuts server
