#!/bin/bash
set -e

# Prompt for Root CA details
read -p "Enter the ROOT CA domain name (e.g., runlocal.dev): " ROOT_CA_DOMAIN_NAME
if [ -z "$ROOT_CA_DOMAIN_NAME" ]; then
    echo "ROOT CA domain name cannot be empty. Exiting."
    exit 1
fi

ROOT_CA_LITERAL_NAME=$(echo "$ROOT_CA_DOMAIN_NAME" | sed 's/\./-/')
WORK_DIR="./${ROOT_CA_LITERAL_NAME}"
ROOT_CA_DIR="${WORK_DIR}/ca"

mkdir -p "${ROOT_CA_DIR}/private"
chmod 700 "${ROOT_CA_DIR}/private"

echo "Creating Root CA for ${ROOT_CA_DOMAIN_NAME}..."

# Generate Root CA private key and certificate
step certificate create "${ROOT_CA_DOMAIN_NAME}" \
  "${ROOT_CA_DIR}/${ROOT_CA_LITERAL_NAME}-root-ca.crt" \
  "${ROOT_CA_DIR}/private/${ROOT_CA_LITERAL_NAME}-root-ca.key" \
  --profile root-ca \
  --no-password --insecure

echo "Root CA created successfully in ${ROOT_CA_DIR}"
