# PKI (Public Key Infrastructure) Management

A comprehensive PKI management system for creating and managing three-tier certificate authorities, intermediate CAs, and TLS certificates using OpenSSL and Step CLI.

## Overview

This project implements a three-tier PKI structure consisting of:
- **Root CA**: The top-level certificate authority
- **Intermediate CA**: Organization/tenant-specific intermediate certificate authorities
- **End-entity certificates**: Server and client certificates for services

It provides two implementations: one using `openssl` and another using `step`.

## Project Structure

```
.
├── openssl/
│   ├── Makefile                    # Main automation targets for OpenSSL
│   ├── root-ca.sh                  # Root CA creation script
│   ├── intermediate-ca.sh          # Intermediate CA creation script
│   ├── server-cert.sh              # Server certificate creation script
│   ├── client-cert.sh              # Client certificate creation script
│   └── runlocal-dev/               # Example PKI deployment
│       ├── runlocal-dev-defaults.conf
│       ├── ca/                     # Root CA files
│       └── bco/                    # Example intermediate CA
│           ├── server-tls/         # Server certificates
│           └── client-tls/         # Client certificates
└── step/
    ├── Makefile                    # Main automation targets for Step CLI
    ├── root-ca.sh                  # Root CA creation script
    ├── intermediate-ca.sh          # Intermediate CA creation script
    ├── server-cert.sh              # Server certificate creation script
    └── client-cert.sh              # Client certificate creation script
```

## Prerequisites

- Bash shell environment
- Make utility
- For the `openssl` implementation: OpenSSL installed
- For the `step` implementation: Step CLI installed

## Quick Start

### Using OpenSSL

1. Navigate to the OpenSSL directory:
```bash
cd openssl
```

2. View available commands:
```bash
make help
```

3. Create a complete PKI setup:
```bash
# Create root CA
make root-ca

# Create intermediate CA
make intermediate-ca

# Create server certificate
make server-cert

# Create client certificate
make client-cert
```

### Using Go CLI

1. Build the CLI:
```bash
go build -o homepki
```

2. Create a complete PKI setup:
```bash
# Create root CA
./homepki root-ca --domain runlocal.dev

# Create intermediate CA
./homepki intermediate-ca --domain runlocal.dev --name siemens

# Create server certificate
./homepki server-cert --domain runlocal.dev --intermediate siemens --server kong-gateway

# Create client certificate
./homepki client-cert --domain runlocal.dev --intermediate siemens --client my-client
```

### Configuration

By default, `homepki` stores all generated certificates and keys in `~/.homepki`.

You can override this location using:
1.  The `--workdir` flag:
    ```bash
    ./homepki root-ca --domain runlocal.dev --workdir /path/to/pki
    ```
2.  The `HOMEPKI_WORKDIR` environment variable:
    ```bash
    export HOMEPKI_WORKDIR=/path/to/pki
    ./homepki root-ca --domain runlocal.dev
    ```

### Using Step CLI

1. Navigate to the Step directory:
```bash
cd step
```

2. View available commands:
```bash
make help
```

3. Create a complete PKI setup:
```bash
# Create root CA
make root-ca

# Create intermediate CA
make intermediate-ca

# Create server certificate
make server-cert

# Create client certificate
make client-cert
```

## Usage Guide

The usage for both `openssl` and `step` implementations is similar. You will be prompted for necessary information like domain names and organization names.

### 1. Creating a Root CA

Run the root CA creation script from either the `openssl` or `step` directory:
```bash
make root-ca
```

You'll be prompted for:
- **Root CA domain name** (e.g., `runlocal.dev`)

This creates:
- Root CA directory structure
- Root CA private key and certificate

### 2. Creating an Intermediate CA

After creating a root CA, create an intermediate CA:
```bash
make intermediate-ca
```

You'll be prompted for:
- **Root CA domain name** (must match existing root CA)
- **Organization/tenant name** (e.g., `bco`, `siemens`)

This creates:
- Intermediate CA directory structure
- Intermediate CA private key and certificate signed by root CA
- Certificate chain file for validation

### 3. Creating Server Certificates

Create TLS certificates for servers:
```bash
make server-cert
```

You'll be prompted for:
- **Root CA domain name**
- **Organization/tenant name** (must match existing intermediate CA)
- **Server name** (e.g., `kong-gateway-clustering`)

This creates server certificates suitable for TLS/SSL services.

### 4. Creating Client Certificates

Create certificates for client authentication:
```bash
make client-cert
```

Similar to server certificates but configured for client authentication use cases.

## Security Features

- **2048-bit RSA keys** for strong encryption
- **Private key protection** (optional with `step`)
- **UTF-8 encoding** for international character support
- **Proper file permissions** (700 for private directories)
- **Certificate database tracking** for revocation management (with `openssl`)
- **Serial number management** for unique certificate identification

## File Organization

### Root CA Structure
```
{domain-name}/
├── ca/
│   ├── {domain-name}-root-ca.crt     # Root certificate
│   └── private/                      # Protected private keys
│       └── {domain-name}-root-ca.key # Root private key
```

### Intermediate CA Structure
```
{domain-name}/
└── {organization}/
    ├── {org}-intermediate-ca.crt     # Intermediate certificate
    ├── {org}-intermediate-ca-chain.crt # Certificate chain
    ├── server-tls/                   # Server certificates
    ├── client-tls/                   # Client certificates
    └── private/                      # Protected private keys
        └── {org}-intermediate-ca.key # Intermediate private key
```

## Configuration

The `openssl` implementation uses OpenSSL configuration files with sensible defaults. The `step` implementation uses command-line flags and profiles for configuration.

- **Key size**: 2048 bits
- **Key protection**: Encrypted private keys (optional with `step`)
- **Extensions**: Proper certificate extensions for CA and end-entity certs

## Best Practices

1. **Secure storage**: Keep private keys in secure, encrypted storage
2. **Access control**: Limit access to CA private keys
3. **Backup**: Regularly backup CA certificates and keys
4. **Rotation**: Plan for certificate renewal and CA rotation
5. **Monitoring**: Track certificate expiration dates

## Example Deployment

The `runlocal-dev` directory (created by the scripts) contains an example PKI deployment for development environments, demonstrating:
- Root CA for `runlocal.dev` domain
- Intermediate CA for `bco` organization
- Server certificates for Kong Gateway clustering
- Client certificates for service authentication

## Troubleshooting

### Common Issues

1. **Permission denied**: Ensure proper file permissions on private directories
2. **Certificate validation**: Check certificate chains and trust relationships
3. **Expired certificates**: Monitor and renew certificates before expiration
4. **Configuration errors**: Validate OpenSSL configuration syntax or `step` command arguments

### Verification Commands

#### OpenSSL
```bash
# Verify certificate
openssl x509 -in certificate.crt -text -noout

# Verify certificate chain
openssl verify -CAfile root-ca.crt -untrusted intermediate-ca.crt end-entity.crt

# Check private key
openssl rsa -in private-key.key -check
```

#### Step CLI
```bash
# Inspect a certificate
step certificate inspect certificate.crt

# Verify a certificate chain
step certificate verify end-entity.crt --roots root-ca.crt --intermediates intermediate-ca.crt
```

## License

This project is for internal use and development purposes.

## Contributing

When contributing to this PKI system:
1. Test all scripts thoroughly in isolated environments
2. Follow existing naming conventions
3. Update documentation for any new features
4. Ensure security best practices are maintained

## Support

For questions or issues with this PKI system, please refer to the OpenSSL or Step CLI documentation or consult with your security team.
