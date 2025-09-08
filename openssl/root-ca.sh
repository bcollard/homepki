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

mkdir -p "${ROOT_CA_DIR}"


#########################################
# CA Database
#########################################
# Create a directory to hold the CA files
mkdir -p "${ROOT_CA_DIR}/db"
mkdir -p "${ROOT_CA_DIR}/private"
chmod 700 "${ROOT_CA_DIR}/private"

# Create an empty index file
touch "${ROOT_CA_DIR}/db/index.db"

# Create a file to hold the next serial number
echo "1000" > "${ROOT_CA_DIR}/db/serial"


#########################################
# OPENSSL DEFAULTS
#########################################
cat > "${WORK_DIR}/${ROOT_CA_LITERAL_NAME}-defaults.conf" <<EOF
### Defaults
default_bits            = 2048                  # RSA key size
encrypt_key             = yes                   # Protect private key
utf8                    = yes                   # Input is UTF-8
string_mask             = utf8only              # Emit UTF-8 strings
prompt                  = no                    # Don't prompt for DN
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always,issuer:always
EOF


#########################################
# OpenSSL config file
#########################################
cat > "${ROOT_CA_DIR}/${ROOT_CA_LITERAL_NAME}.conf" <<EOF
# Include defaults
.include ${WORK_DIR}/${ROOT_CA_LITERAL_NAME}-defaults.conf

### ROOT CA
# used for the root CA CSR
[ req ]
distinguished_name      = root_ca_dn                          # DN section
req_extensions          = root_ca_ext                         # Desired extensions

# used for the root CA CSR
[ root_ca_dn ]
organizationName        = ${ROOT_CA_LITERAL_NAME}
commonName              = ${ROOT_CA_DOMAIN_NAME}

# used for the root CA CSR
[ root_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true,pathlen:1

# used for self-signing the root CA
# also used when signing intermediate CAs (accounts/organizations)
[ ca ]
default_ca              = CA_default                          # The default ca section

[ CA_default ]
certificate             = ${ROOT_CA_DIR}/${ROOT_CA_LITERAL_NAME}-root-ca.crt            # The CA cert
dir                     = ${ROOT_CA_DIR}                                                # Where everything is kept
private_key             = ${ROOT_CA_DIR}/private/${ROOT_CA_LITERAL_NAME}-root-ca.key    # The CA private key
database                = ${ROOT_CA_DIR}/db/index.db                                    # The CA database
serial                  = ${ROOT_CA_DIR}/db/serial                                      # The current serial number
policy                  = match_pol                                                     # The CA policy
new_certs_dir           = ${ROOT_CA_DIR}                                                # New certs will be placed here
default_md              = sha256                                                        # MD to use
name_opt                = multiline,-esc_msb,utf8                                       # Subject DN display options
default_days            = 2190                                                          # How long to certify for
x509_extensions         = root_ca_ext                                                   # Desired extensions

[ match_pol ]
countryName             = optional              # Must match 'NO'
stateOrProvinceName     = optional              # Included if present
localityName            = optional              # Included if present
organizationName        = match                 # Must match "${ROOT_CA_LITERAL_NAME}"
organizationalUnitName  = optional              # Included if present
commonName              = supplied              # Must be present

# only used when signing intermediate CAs (accounts/organizations)
[ signing_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true,pathlen:0
subjectKeyIdentifier    = hash
EOF

#########################################
# ROOT CA
#########################################
# create the CA request
openssl req -new -nodes -sha256 -newkey rsa:2048 \
  -config "${ROOT_CA_DIR}/${ROOT_CA_LITERAL_NAME}.conf" \
  -keyout "${ROOT_CA_DIR}/private/${ROOT_CA_LITERAL_NAME}-root-ca.key" \
  -out "${ROOT_CA_DIR}/${ROOT_CA_LITERAL_NAME}-root-ca.csr"
  
# self-sign the CA
openssl ca -selfsign -batch \
  -config "${ROOT_CA_DIR}/${ROOT_CA_LITERAL_NAME}.conf" \
  -in "${ROOT_CA_DIR}/${ROOT_CA_LITERAL_NAME}-root-ca.csr" \
  -out "${ROOT_CA_DIR}/${ROOT_CA_LITERAL_NAME}-root-ca.crt"

