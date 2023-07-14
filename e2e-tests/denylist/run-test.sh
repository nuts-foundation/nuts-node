#!/usr/bin/env bash

source ../util.sh

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
docker compose down
if [ $? -ne 0 ]; then
	echo "ERROR: failed to shut down old containers"
	exitWithDockerLogs 1
fi

docker compose rm -f -v
if [ $? -ne 0 ]; then
	echo "ERROR: failed to remove old containers"
	exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up --wait
if [ $? -ne 0 ]; then
	echo "ERROR: failed to start containers"
	exitWithDockerLogs 1
fi

sleep 5

# Simply to log this
openssl version

echo "------------------------------------"
echo "Connecting with allowed cert.."
echo "------------------------------------"
for x in $(seq 100); do
	# Connect to the nuts-node with a valid client certificate
	#curl --fail --cert client-allowed.crt --key client-allowed.key "https://localhost:1323/status/diagnostics"
	openssl s_client -connect localhost:15555 -cert client-allowed.crt -key client-allowed.key -CAfile truststore-development.pem -verify_return_error -tls1_2 < <(echo "Hello Nuts 🥜")
	if [ $? -ne 0 ]; then
		echo "ERROR: failed to contact nuts-node with valid certificate"
		exitWithDockerLogs 1
	fi
done

echo "------------------------------------"
echo "Connecting 100x with blocked cert (tls v1.2).."
echo "------------------------------------"
for x in $(seq 100); do
	# Connect to the nuts-node with a blocked client certificate
	curl --http2 -k https://localhost:15555 --cert client-blocked.crt --key client-blocked.key -vvv --fail --tlsv1.2
	if [ $? -eq 0 ]; then
		echo "ERROR: blocked certificate was allowed to connect (tls v1.2)"
		exitWithDockerLogs 1
	else
		echo "PASS: server rejected certificate as expected (tls v1.2)"
	fi
done

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
if [ $? -ne 0 ]; then
	echo "ERROR: failed to stop docker containers"
	exitWithDockerLogs 1
fi
