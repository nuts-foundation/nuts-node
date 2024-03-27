#!/usr/bin/env bash
source ../../util.sh

TEST_REPEAT_COUNT=20

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
echo "Connecting (defaults) with allowed cert.."
echo "------------------------------------"
for x in $(seq ${TEST_REPEAT_COUNT}); do
	# Connect to the nuts-node with a valid client certificate
	#curl --fail --cert client-allowed.crt --key client-allowed.key "https://localhost:8081/status/diagnostics"
	openssl s_client -connect localhost:15555 -cert ../client-allowed.crt -key ../client-allowed.key -CAfile ../truststore-development.pem -verify_return_error -tls1_2 < <(echo "Hello Nuts 🥜")
	if [ $? -ne 0 ]; then
		echo "ERROR: failed to contact nuts-node-defaults with valid certificate"
		exitWithDockerLogs 1
	fi

	# Check the logs have the right contents
	docker logs denylist-nuts-node-defaults 2>&1 | tail -n1 | grep 'Validated certificate'
	if [ $? -ne 0 ]; then
		echo "ERROR: Failed to find certificate validation log message for nuts-node-defaults (tls v1.2)"
		exitWithDockerLogs 1
	fi
done

echo "------------------------------------"
echo "Connecting (defaults) with blocked cert (tls v1.2).."
echo "------------------------------------"
for x in $(seq ${TEST_REPEAT_COUNT}); do
	# Connect to the nuts-node with a blocked client certificate
	openssl s_client -connect localhost:15555 -cert ../client-blocked.crt -key ../client-blocked.key -CAfile ../truststore-development.pem -verify_return_error -tls1_2 < <(echo "Hello Nuts 🥜")
	if [ $? -eq 0 ]; then
		echo "ERROR: blocked certificate was allowed to connect to nuts-node-defaults (tls v1.2)"
		exitWithDockerLogs 1
	else
		echo "PASS: server rejected certificate as expected (tls v1.2)"
	fi

	# Check the logs have the right contents
	docker logs denylist-nuts-node-defaults 2>&1 | tail -n1 | grep 'Rejecting banned certificate'
	if [ $? -ne 0 ]; then
		echo "ERROR: Failed to find certificate rejection log message for nuts-node-defaults (tls v1.2)"
		exitWithDockerLogs 1
	fi
done

echo "------------------------------------"
echo "Connecting (defaults) with blocked cert (tls v1.3).."
echo "------------------------------------"
for x in $(seq ${TEST_REPEAT_COUNT}); do
	# Connect to the nuts-node with a blocked client certificate
	openssl s_client -connect localhost:15555 -cert client-blocked.crt -key client-blocked.key -CAfile ../truststore-development.pem -verify_return_error -tls1_3 < <(echo "Hello Nuts 🥜")
	# Ignore exit code from openssl with tls v1.3 because it is unreliable.
	# Depend entirely on the log check below instead.

	# Check the logs have the right contents
	docker logs denylist-nuts-node-defaults 2>&1 | tail -n1 | grep 'Rejecting banned certificate'
	if [ $? -ne 0 ]; then
		echo "ERROR: Failed to find certificate rejection log message for nuts-node-defaults (tls v1.3)"
		exitWithDockerLogs 1
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
