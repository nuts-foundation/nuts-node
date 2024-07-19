#!/usr/bin/env bash
# Register Party A
PARTY_A_DIDDOC=$(docker compose exec nodeA-backend nuts vdr create-did --v2)
PARTY_A_DID=$(echo $PARTY_A_DIDDOC | jq -r .[0].id)
echo Party A DID: $PARTY_A_DID

# Register Vendor B
PARTY_B_DIDDOC=$(docker compose exec nodeB-backend nuts vdr create-did --v2)
PARTY_B_DID=$(echo $PARTY_B_DIDDOC | jq -r .[0].id)
echo Party B DID: $PARTY_B_DID