# #########################################
# # CLIENT CERT
# #########################################
# cat > ${ROOT_CA_DIR}/${INTERMEDIATE_CA_NAME}-x509-client-${CLUSTER1_NAME}-req.conf <<EOF
# # Include defaults
# .include ${ROOT_CA_DIR}/${ROOT_CA_LITERAL_NAME}-defaults.conf

# ### Client cert
# [ client_req ]
# distinguished_name      = client_dn                # DN section
# req_extensions          = client_ext               # Desired extensions
# days                    = 365                      # How long to certify for

# [ client_dn ]
# organizationName        = ${INTERMEDIATE_CA_NAME}
# commonName              = ${CLUSTER1_NAME}.${INTERMEDIATE_CA_NAME}.runlocal.dev

# [ client_ext ]
# keyUsage                = critical,digitalSignature
# basicConstraints        = CA:false
# extendedKeyUsage        = clientAuth
# subjectAltName          = critical, @client_alt_names

# [ client_alt_names ]
# URI = ${CLUSTER1_NAME}.${INTERMEDIATE_CA_NAME}.runlocal.dev
# DNS.1 = ${CLUSTER1_NAME}.${INTERMEDIATE_CA_NAME}.runlocal.dev
# IP.1 = ${GATEWAY_IP}
# EOF


