#!/bin/bash
set -e

# Prompt for CA details
read -p "Enter the ROOT CA domain name (e.g., runlocal.dev): " ROOT_CA_DOMAIN_NAME
if [ -z "$ROOT_CA_DOMAIN_NAME" ]; then
    echo "ROOT CA domain name cannot be empty. Exiting."
    exit 1
fi

read -p "Enter a new account/tenant name for the Organization Name in the intermediate CA (e.g., 'bco'): " INTERMEDIATE_CA_NAME
if [ -z "$INTERMEDIATE_CA_NAME" ]; then
    echo "Intermediate CA name cannot be empty. Exiting."
    exit 1
fi

ROOT_CA_LITERAL_NAME=$(echo "$ROOT_CA_DOMAIN_NAME" | sed 's/\./-/')
WORK_DIR="./${ROOT_CA_LITERAL_NAME}"
ROOT_CA_DIR="${WORK_DIR}/ca"
INTERMEDIATE_CA_DIR="${WORK_DIR}/${INTERMEDIATE_CA_NAME}"

mkdir -p "${INTERMEDIATE_CA_DIR}/private"
chmod 700 "${INTERMEDIATE_CA_DIR}/private"

ROOT_CA_CERT="${ROOT_CA_DIR}/${ROOT_CA_LITERAL_NAME}-root-ca.crt"
ROOT_CA_KEY="${ROOT_CA_DIR}/private/${ROOT_CA_LITERAL_NAME}-root-ca.key"

if [ ! -f "$ROOT_CA_CERT" ] || [ ! -f "$ROOT_CA_KEY" ]; then
    echo "Root CA certificate or key not found. Please create the Root CA first."
    exit 1
fi

echo "Creating Intermediate CA for ${INTERMEDIATE_CA_NAME}..."

# Generate Intermediate CA private key and certificate
step certificate create "${INTERMEDIATE_CA_NAME}.${ROOT_CA_DOMAIN_NAME}" \
  "${INTERMEDIATE_CA_DIR}/${INTERMEDIATE_CA_NAME}-intermediate-ca.crt" \
  "${INTERMEDIATE_CA_DIR}/private/${INTERMEDIATE_CA_NAME}-intermediate-ca.key" \
  --profile intermediate-ca \
  --ca "${ROOT_CA_CERT}" \
  --ca-key "${ROOT_CA_KEY}" \
  --no-password --insecure

# Create certificate chain
cat "${INTERMEDIATE_CA_DIR}/${INTERMEDIATE_CA_NAME}-intermediate-ca.crt" \
  "${ROOT_CA_CERT}" > \
  "${INTERMEDIATE_CA_DIR}/${INTERMEDIATE_CA_NAME}-intermediate-ca-chain.crt"

echo "Intermediate CA created successfully in ${INTERMEDIATE_CA_DIR}"
