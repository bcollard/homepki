##########################
# ROOT CA Env init
##########################
# Prompt the user for the domain name
read -p "Enter the ROOT CA domain name (e.g., runlocal.dev): " ROOT_CA_DOMAIN_NAME

# --- Dynamic Variable Generation ---
# If the user enters an empty string, exit.
if [ -z "$ROOT_CA_DOMAIN_NAME" ]; then
    echo "ROOT CA domain name cannot be empty. Exiting."
    exit 1
fi

# Derive other names from the domain name provided.
# This replaces the first dot with a hyphen for the literal name and directory.
# Example: 'runlocal.dev' becomes 'runlocal-dev'
ROOT_CA_LITERAL_NAME=$(echo "$ROOT_CA_DOMAIN_NAME" | sed 's/\./-/')
WORK_DIR="./${ROOT_CA_LITERAL_NAME}"
ROOT_CA_DIR="${WORK_DIR}/ca"


##########################
# Intermediate CA Env init
##########################
# Prompt the user for the domain name
read -p "Enter a new account/tenant name for the Organization Name in the intermediate CA (e.g., "siemens"): " INTERMEDIATE_CA_NAME

# --- Dynamic Variable Generation ---
# If the user enters an empty string, exit.
if [ -z "$INTERMEDIATE_CA_NAME" ]; then
    echo "Intermediate CA domain name cannot be empty. Exiting."
    exit 1
fi

INTERMEDIATE_CA_DIR="${WORK_DIR}/${INTERMEDIATE_CA_NAME}"
mkdir -p ${INTERMEDIATE_CA_DIR}



#########################################
# Intermediate CA Database
#########################################
# Create a directory to hold the CA files
mkdir -p ${INTERMEDIATE_CA_DIR}/db
mkdir -p ${INTERMEDIATE_CA_DIR}/private
chmod 700 ${INTERMEDIATE_CA_DIR}/private

# Create an empty index file
touch ${INTERMEDIATE_CA_DIR}/db/index.db

# Create a file to hold the next serial number
echo "1000" > ${INTERMEDIATE_CA_DIR}/db/serial


#########################################
# OpenSSL config file
#########################################
cat > ${INTERMEDIATE_CA_DIR}/${INTERMEDIATE_CA_NAME}.conf <<EOF
# Include defaults
.include ${WORK_DIR}/${ROOT_CA_LITERAL_NAME}-defaults.conf

### TLS CA
# used for the intermediate CA CSR
[ req ]
distinguished_name      = tls_ca_dn                 # DN section
req_extensions          = tls_ca_ext             # Desired extensions

# used for the intermediate CA CSR
[ tls_ca_dn ]
organizationName        = ${ROOT_CA_LITERAL_NAME}
organizationalUnitName  = ${INTERMEDIATE_CA_NAME}
commonName              = ${INTERMEDIATE_CA_NAME}.${ROOT_CA_DOMAIN_NAME}

# used for the intermediate CA CSR
[ tls_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true,pathlen:0

# only used when signing leaf certificates (client or server)
[ ca ]
default_ca              = CA_default                          # The default ca section

[ CA_default ]
certificate             = ${INTERMEDIATE_CA_DIR}/${INTERMEDIATE_CA_NAME}-intermediate-ca.crt               # The CA cert
dir                     = ${INTERMEDIATE_CA_DIR}                   # Where everything is kept
private_key             = ${INTERMEDIATE_CA_DIR}/private/${INTERMEDIATE_CA_NAME}-intermediate-ca.key   # The CA private key
database                = ${INTERMEDIATE_CA_DIR}/db/index.db           # The CA database
serial                  = ${INTERMEDIATE_CA_DIR}/db/serial             # The current serial number
policy                  = match_pol                     # The CA policy
new_certs_dir           = ${INTERMEDIATE_CA_DIR}                       # New certs will be placed here
default_md              = sha256                              # MD to use
name_opt                = multiline,-esc_msb,utf8                                       # Subject DN display options
default_days            = 2190                                # How long to certify for
x509_extensions         = tls_ca_ext                          # Desired extensions

[ match_pol ]
countryName             = optional              # Must match 'NO'
stateOrProvinceName     = optional              # Included if present
localityName            = optional              # Included if present
organizationName        = match                 # Must match "${INTERMEDIATE_CA_NAME}"
organizationalUnitName  = match              # Included if present
commonName              = supplied              # Must be present

# only used when signing leaf server certificates
[ server_ext ]
keyUsage                = critical,digitalSignature,keyEncipherment
basicConstraints        = CA:false
extendedKeyUsage        = serverAuth
subjectKeyIdentifier    = hash

# only used when signing leaf client certificates
[ client_ext ]
keyUsage                = critical,digitalSignature
basicConstraints        = CA:false
extendedKeyUsage        = clientAuth
subjectKeyIdentifier    = hash
EOF


#########################################
# Intermediate TLS CA
#########################################
# create the intermediate TLS CA request
openssl req -new -nodes -sha256 -newkey rsa:2048 \
  -config ${INTERMEDIATE_CA_DIR}/${INTERMEDIATE_CA_NAME}.conf \
  -keyout ${INTERMEDIATE_CA_DIR}/private/${INTERMEDIATE_CA_NAME}-intermediate-ca.key \
  -out ${INTERMEDIATE_CA_DIR}/${INTERMEDIATE_CA_NAME}-intermediate-ca.csr

# sign the intermediate TLS CA with the root CA
openssl ca -batch \
  -config ${ROOT_CA_DIR}/${ROOT_CA_LITERAL_NAME}.conf \
  -extensions signing_ca_ext \
  -in ${INTERMEDIATE_CA_DIR}/${INTERMEDIATE_CA_NAME}-intermediate-ca.csr \
  -out ${INTERMEDIATE_CA_DIR}/${INTERMEDIATE_CA_NAME}-intermediate-ca.crt


#########################################
# Certificate chain
#########################################
# Create the certificate chain file
cat ${INTERMEDIATE_CA_DIR}/${INTERMEDIATE_CA_NAME}-intermediate-ca.crt \
  ${ROOT_CA_DIR}/${ROOT_CA_LITERAL_NAME}-root-ca.crt > \
  ${INTERMEDIATE_CA_DIR}/${INTERMEDIATE_CA_NAME}-intermediate-ca-chain.crt

