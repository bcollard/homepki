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

# Trust the root CA system-wide (macOS)
homepki trust install --domain runlocal.dev
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
│   ├── sign.go                     # sign command (external CSRs)
│   ├── trust.go                    # trust install/uninstall/status (macOS)
│   ├── paths.go                    # shared --force and --key-type handling
│   └── skill.go                    # skill install + path
└── pkg/
    └── pki/
        ├── pki.go                  # PKI helpers (OpenSSL wrappers, cert parsing)
        ├── keys.go                 # --key-type → openssl key generation arguments
        ├── csr.go                  # CSR loading and subject policy checks
        ├── db.go                   # openssl CA database (index.db) edits
        └── trust.go                # macOS trust store commands
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

### 5. Signing an External CSR

Sign a request generated elsewhere — the private key never reaches homepki:

```bash
openssl req -new -nodes -newkey rsa:2048 -keyout my-service.key -out my-service.csr \
  -subj "/O=runlocal-dev/OU=bu1/CN=my-service.bu1.runlocal.dev" \
  -addext "subjectAltName=DNS:my-service.bu1.runlocal.dev,DNS:my-service.local"

homepki sign --domain runlocal.dev --intermediate bu1 --csr my-service.csr

# As a client certificate, under a chosen name
homepki sign --domain runlocal.dev --intermediate bu1 --csr my-client.csr \
  --type client --name my-client

# Write the certificate outside the PKI tree
homepki sign --domain runlocal.dev --intermediate bu1 --csr my-service.csr \
  --out ./my-service.crt
```

The request's subject must carry the root CA's organization (`O=`, dots replaced by dashes) and the intermediate's organizational unit (`OU=`). Mismatches are rejected before OpenSSL runs, with the exact `-subj` to use printed in the error. Subject Alternative Names are copied from the request.

### Trusting the Root CA (macOS)

Add the root CA to the macOS system keychain so Safari, Chrome, curl and anything else reading the system trust store accept certificates issued under it:

```bash
homepki trust install --domain runlocal.dev     # writes to the System keychain (sudo)
homepki trust status                            # every root CA in the workdir
homepki trust status --domain runlocal.dev -o json
homepki trust uninstall --domain runlocal.dev   # drop the trust setting (sudo)
```

`install` and `uninstall` run `security` under `sudo` and may prompt for your password. `status` needs no privileges.

This is macOS-only, and it covers the system keychain alone — Firefox and Java keep their own trust stores. Servers must still present the intermediate chain file, or clients cannot build the path from the leaf to the trusted root.

### Key Types

Every generate command takes `--key-type`: `rsa` (2048-bit, the default), `ecdsa` / `ecdsa-p256`, `ecdsa-p384`, or `ecdsa-p521`. Tiers are independent, so an ECDSA leaf under an RSA intermediate is fine.

```bash
homepki intermediate-ca --domain runlocal.dev --name bu1 --key-type ecdsa
homepki server-cert --domain runlocal.dev --intermediate bu1 --server gw --key-type ecdsa-p384
```

### Re-issuing

Generate commands refuse to overwrite existing material: a re-run exits 1, prints what is in the way, and changes nothing. `--force` replaces it.

```bash
homepki server-cert --domain runlocal.dev --intermediate bu1 --server kong-gateway --force
```

For a leaf, `--force` also drops the subject's row from the intermediate's CA database, which is what lets the same name be issued again. For a CA tier, `--force` orphans every certificate beneath it — check the tier *below* the one you replaced, since it is the only one whose chain flips to invalid.

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

- **2048-bit RSA keys by default**, or ECDSA P-256/P-384/P-521 via `--key-type`
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

- **Key**: 2048-bit RSA (`--key-type ecdsa` for P-256, `ecdsa-p384`, `ecdsa-p521`)
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
