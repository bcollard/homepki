# homepki

A simple PKI management tool for local development. Create and manage three-tier certificate authorities, intermediate CAs, and TLS certificates with a single CLI.

📖 **[bcollard.github.io/homepki](https://bcollard.github.io/homepki/)**

## Install

```bash
brew tap bcollard/homepki
brew install --cask homepki
```

## Quick Start

```bash
# Create root CA
homepki root-ca --domain runlocal.dev

# Create intermediate CA
homepki intermediate-ca --domain runlocal.dev --name bu1

# Create server certificate
homepki server-cert --domain runlocal.dev --intermediate bu1 --server kong-gateway

# Create client certificate
homepki client-cert --domain runlocal.dev --intermediate bu1 --client my-client
```

Certificates and keys are stored in `~/.homepki` by default.

## Configuration

Override the default storage location using:

- The `--workdir` flag:
  ```bash
  homepki root-ca --domain runlocal.dev --workdir /path/to/pki
  ```
- The `HOMEPKI_WORKDIR` environment variable:
  ```bash
  export HOMEPKI_WORKDIR=/path/to/pki
  homepki root-ca --domain runlocal.dev
  ```

## Agent Skill (AI coding tools)

homepki ships an [Agent Skill](https://code.claude.com/docs/en/skills) that teaches AI coding tools how to drive homepki — issuing TLS and mTLS material for scripts, demos, and tests. Install it once and every future agent session knows how to use homepki without you explaining it each time:

```bash
homepki skill install          # → ~/.claude/skills/homepki/SKILL.md
homepki skill install --force  # overwrite an existing copy (e.g. after upgrading homepki)
homepki skill path             # print the install path
homepki skill install --print  # emit the skill to stdout (pipe it anywhere)
```

The skill is embedded in the binary, so no download is needed. Start a new agent session after installing to pick it up.

## Overview

`homepki` implements a three-tier PKI structure:
- **Root CA**: The top-level certificate authority
- **Intermediate CA**: Organization/tenant-specific intermediate certificate authorities
- **End-entity certificates**: Server and client certificates for services

## Build from Source

```bash
go build -o homepki
```

## Project Structure

```
.
├── main.go                         # Entry point
├── skill.go                        # Embeds SKILL.md into the binary
├── SKILL.md                        # Agent Skill definition (single source of truth)
├── go.mod
├── cmd/
│   ├── root.go                     # CLI setup, --workdir flag
│   ├── root_ca.go                  # root-ca command (generate + list)
│   ├── intermediate_ca.go          # intermediate-ca command (generate + list)
│   ├── server_cert.go              # server-cert command (generate + list)
│   ├── client_cert.go              # client-cert command (generate + list)
│   └── skill.go                    # skill install + path
└── pkg/
    └── pki/
        └── pki.go                  # PKI helpers (OpenSSL wrappers, cert parsing)
```

## Usage Guide

### 1. Creating a Root CA

```bash
homepki root-ca --domain runlocal.dev

# List root CAs (table, default)
homepki root-ca list

# List as JSON
homepki root-ca list -o json
```

This creates:
- Root CA directory structure
- Root CA private key and self-signed certificate

### 2. Creating an Intermediate CA

```bash
homepki intermediate-ca --domain runlocal.dev --name bu1

# List intermediate CAs (table, default)
homepki intermediate-ca list --domain runlocal.dev

# List as JSON
homepki intermediate-ca list --domain runlocal.dev -o json
```

This creates:
- Intermediate CA private key and certificate signed by the root CA
- Certificate chain file (`{name}-intermediate-ca-chain.crt`)

### 3. Creating Server Certificates

```bash
homepki server-cert --domain runlocal.dev --intermediate bu1 --server kong-gateway

# List server certificates (table, default)
homepki server-cert list --domain runlocal.dev --intermediate bu1

# List as JSON
homepki server-cert list --domain runlocal.dev --intermediate bu1 -o json
```

### 4. Creating Client Certificates

```bash
homepki client-cert --domain runlocal.dev --intermediate bu1 --client my-service

# List client certificates (table, default)
homepki client-cert list --domain runlocal.dev --intermediate bu1

# List as JSON
homepki client-cert list --domain runlocal.dev --intermediate bu1 -o json
```

### Listing and Chain Verification

All `list` subcommands verify the certificate's chain of trust and support two output formats via `-o`/`--output`:

| Format | Description |
|--------|-------------|
| `table` | Human-readable table with coloured chain status (default) |
| `json`  | Machine-readable JSON array, no extra output |

Chain validity is checked at list time:
- `root-ca list` — verifies each root cert is validly self-signed
- `intermediate-ca list` — verifies the intermediate was signed by the root CA
- `server-cert list` / `client-cert list` — verifies the leaf cert chains through the intermediate to the root CA

Example JSON output:
```json
[
  {
    "name": "kong-gateway.crt",
    "expires": "2027-04-01",
    "days_left": 360,
    "chain_valid": true
  },
  {
    "name": "old.crt",
    "expires": "2025-01-01",
    "days_left": -270,
    "chain_valid": false,
    "chain_error": "x509: certificate has expired or is not yet valid"
  }
]
```

## Security Features

- **2048-bit RSA keys** for strong encryption
- **UTF-8 encoding** for international character support
- **Proper file permissions** (700 for private directories)
- **Certificate database tracking** for revocation management
- **Serial number management** for unique certificate identification
- **Chain verification** on all `list` commands

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

## Defaults

- **Key size**: 2048-bit RSA
- **Digest**: SHA-256
- **Validity**: 365 days for leaf certs, 2190 days (~6 years) for CAs
- **Extensions**: Proper X.509 extensions for CA and end-entity certificates

## Best Practices

1. **Secure storage**: Keep private keys in secure, encrypted storage
2. **Access control**: Limit access to CA private keys
3. **Backup**: Regularly backup CA certificates and keys
4. **Rotation**: Plan for certificate renewal and CA rotation
5. **Monitoring**: Track certificate expiration dates

## Troubleshooting

### Common Issues

1. **Permission denied**: Ensure proper file permissions on private directories
2. **Certificate validation**: Check certificate chains and trust relationships
3. **Expired certificates**: Monitor and renew certificates before expiration
4. **Configuration errors**: Validate OpenSSL configuration syntax

### Verification Commands

```bash
# Inspect a certificate
openssl x509 -in certificate.crt -text -noout

# Manually verify a certificate chain
openssl verify -CAfile root-ca.crt -untrusted intermediate-ca.crt end-entity.crt

# Check a private key
openssl rsa -in private-key.key -check
```

## License

MIT — see [LICENSE](LICENSE).

## Contributing

1. Test changes thoroughly in isolated environments
2. Follow existing naming conventions
3. Ensure security best practices are maintained
