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
# CLIENT CERT Env init
#########################
# Prompt the user for the client name
read -p "Enter the client name (e.g., "my-client"): " CLIENT_NAME

CLIENT_DIR="${WORK_DIR}/${INTERMEDIATE_CA_NAME}/client-tls"
mkdir -p "${CLIENT_DIR}"



###########################
# OpenSSL config
###########################
cat > "${CLIENT_DIR}/${CLIENT_NAME}.conf" <<EOF
# Include defaults
.include ${WORK_DIR}/${ROOT_CA_LITERAL_NAME}-defaults.conf


### Client cert
[ req ]
distinguished_name      = client_dn                # DN section
req_extensions          = client_ext               # Desired extensions

[ client_dn ]
organizationName        = ${ROOT_CA_LITERAL_NAME}
organizationalUnitName  = ${INTERMEDIATE_CA_NAME}
commonName              = ${CLIENT_NAME}.${INTERMEDIATE_CA_NAME}.${ROOT_CA_DOMAIN_NAME}

[ client_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:false
extendedKeyUsage        = clientAuth
subjectAltName          = critical, @client_alt_names

[ client_alt_names ]
DNS.1 = ${CLIENT_NAME}.${INTERMEDIATE_CA_NAME}.${ROOT_CA_DOMAIN_NAME}
EOF


#########################################
# CLIENT CERT
#########################################
# create the Client cert request
openssl req -new -nodes -sha256 -newkey rsa:2048 \
  -config "${CLIENT_DIR}/${CLIENT_NAME}.conf" \
  -keyout "${CLIENT_DIR}/${CLIENT_NAME}-client.key" \
  -out "${CLIENT_DIR}/${CLIENT_NAME}-client.csr"

# sign the client cert with the intermediate CA
openssl ca -batch \
  -config "${INTERMEDIATE_CA_DIR}/${INTERMEDIATE_CA_NAME}.conf" \
  -extensions client_ext \
  -in "${CLIENT_DIR}/${CLIENT_NAME}-client.csr" \
  -out "${CLIENT_DIR}/${CLIENT_NAME}-client.crt" \
  -days 365



