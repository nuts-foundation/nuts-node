#!/usr/bin/env bash
PARTY_A_DIDDOC=$(curl -s -X POST -H "Content-Type:application/json" -d '{"did": "did:web:nodeA"}' http://localhost:18081/internal/vdr/v2/did)
PARTY_A_DID=$(echo $PARTY_A_DIDDOC | jq -r .id)
echo Party A DID: $PARTY_A_DID

PARTY_B_DIDDOC=$(curl -s -X POST -H "Content-Type:application/json" -d '{"did": "did:web:nodeB"}' http://localhost:28081/internal/vdr/v2/did)
PARTY_B_DID=$(echo $PARTY_B_DIDDOC | jq -r .id)
echo Party B DID: $PARTY_B_DID
