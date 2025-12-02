#!/usr/bin/env bash
set -euo pipefail

##########################
# ROOT CA Env init
##########################
# Prompt the user for the domain name
read -p "Enter the ROOT CA domain name (e.g., runlocal.dev): " ROOT_CA_DOMAIN_NAME

# --- Dynamic Variable Generation ---
# If the user enters an empty string, exit.
if [ -z "${ROOT_CA_DOMAIN_NAME}" ]; then
    echo "ROOT CA domain name cannot be empty. Exiting."
    exit 1
fi

# Derive other names from the domain name provided.
# This replaces the first dot with a hyphen for the literal name and directory.
# Example: 'runlocal.dev' becomes 'runlocal-dev'
ROOT_CA_LITERAL_NAME=$(echo "${ROOT_CA_DOMAIN_NAME}" | sed 's/\./-/')
WORK_DIR="./${ROOT_CA_LITERAL_NAME}"
ROOT_CA_DIR="${WORK_DIR}/ca"


##########################
# Intermediate CA Env init
##########################
# Prompt the user for the domain name
read -p "Enter a new account/tenant name for the Organization Name in the intermediate CA (e.g., "siemens"): " INTERMEDIATE_CA_NAME

# --- Dynamic Variable Generation ---
# If the user enters an empty string, exit.
if [ -z "${INTERMEDIATE_CA_NAME}" ]; then
    echo "Intermediate CA domain name cannot be empty. Exiting."
    exit 1
fi

INTERMEDIATE_CA_DIR="${WORK_DIR}/${INTERMEDIATE_CA_NAME}"
mkdir -p "${INTERMEDIATE_CA_DIR}"



#########################
# SERVER CERT Env init
#########################
# Prompt the user for the server name
read -p "Enter the server name (e.g., "kong-gateway-clustering"): " SERVER_NAME

SERVER_DIR="${WORK_DIR}/${INTERMEDIATE_CA_NAME}/server-tls"
mkdir -p "${SERVER_DIR}"



###########################
# OpenSSL config
###########################
cat > "${SERVER_DIR}/${SERVER_NAME}.conf" <<EOF
# Include defaults
.include ${WORK_DIR}/${ROOT_CA_LITERAL_NAME}-defaults.conf


### Server cert
[ req ]
distinguished_name      = server_dn                # DN section
req_extensions          = server_ext               # Desired extensions

[ server_dn ]
organizationName        = ${ROOT_CA_LITERAL_NAME}
organizationalUnitName  = ${INTERMEDIATE_CA_NAME}
commonName              = ${SERVER_NAME}.${INTERMEDIATE_CA_NAME}.${ROOT_CA_DOMAIN_NAME}

[ server_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:false
extendedKeyUsage        = serverAuth
subjectAltName          = critical, @server_alt_names

[ server_alt_names ]
DNS.1 = ${SERVER_NAME}.${INTERMEDIATE_CA_NAME}.${ROOT_CA_DOMAIN_NAME}
EOF


#########################################
# SERVER CERT
#########################################
# create the Server cert request
openssl req -new -nodes -sha256 -newkey rsa:2048 \
  -config "${SERVER_DIR}/${SERVER_NAME}.conf" \
  -keyout "${SERVER_DIR}/${SERVER_NAME}.key" \
  -out "${SERVER_DIR}/${SERVER_NAME}.csr"

# sign the server cert with the intermediate CA
openssl ca -batch \
  -config "${INTERMEDIATE_CA_DIR}/${INTERMEDIATE_CA_NAME}.conf" \
  -extensions server_ext \
  -in "${SERVER_DIR}/${SERVER_NAME}.csr" \
  -out "${SERVER_DIR}/${SERVER_NAME}.crt" \
  -days 365



