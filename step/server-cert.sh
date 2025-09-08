#!/bin/bash
set -e

# Prompt for details
read -p "Enter the ROOT CA domain name (e.g., runlocal.dev): " ROOT_CA_DOMAIN_NAME
if [ -z "$ROOT_CA_DOMAIN_NAME" ]; then
    echo "ROOT CA domain name cannot be empty. Exiting."
    exit 1
fi

read -p "Enter the account/tenant name for the intermediate CA (e.g., 'bco'): " INTERMEDIATE_CA_NAME
if [ -z "$INTERMEDIATE_CA_NAME" ]; then
    echo "Intermediate CA name cannot be empty. Exiting."
    exit 1
fi

read -p "Enter the server name (e.g., 'kong-gateway-clustering'): " SERVER_NAME
if [ -z "$SERVER_NAME" ]; then
    echo "Server name cannot be empty. Exiting."
    exit 1
fi

ROOT_CA_LITERAL_NAME=$(echo "$ROOT_CA_DOMAIN_NAME" | sed 's/\./-/')
WORK_DIR="./${ROOT_CA_LITERAL_NAME}"
INTERMEDIATE_CA_DIR="${WORK_DIR}/${INTERMEDIATE_CA_NAME}"
SERVER_DIR="${INTERMEDIATE_CA_DIR}/server-tls"

mkdir -p "${SERVER_DIR}"

INTERMEDIATE_CA_CERT="${INTERMEDIATE_CA_DIR}/${INTERMEDIATE_CA_NAME}-intermediate-ca.crt"
INTERMEDIATE_CA_KEY="${INTERMEDIATE_CA_DIR}/private/${INTERMEDIATE_CA_NAME}-intermediate-ca.key"

if [ ! -f "$INTERMEDIATE_CA_CERT" ] || [ ! -f "$INTERMEDIATE_CA_KEY" ]; then
    echo "Intermediate CA certificate or key not found. Please create the Intermediate CA first."
    exit 1
fi

echo "Creating server certificate for ${SERVER_NAME}..."

# Generate server certificate
step certificate create "${SERVER_NAME}.${INTERMEDIATE_CA_NAME}.${ROOT_CA_DOMAIN_NAME}" \
  "${SERVER_DIR}/${SERVER_NAME}-server.crt" \
  "${SERVER_DIR}/${SERVER_NAME}-server.key" \
  --profile leaf \
  --ca "${INTERMEDIATE_CA_CERT}" \
  --ca-key "${INTERMEDIATE_CA_KEY}" \
  --no-password --insecure

echo "Server certificate created successfully in ${SERVER_DIR}"
