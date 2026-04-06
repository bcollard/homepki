# homepki

## Build & Run

```bash
go build ./...
go run . <command>
```

Version metadata is injected at build time via goreleaser (`-ldflags`). During development `version=dev`, `commit=none`, `date=unknown`.

## Project Layout

```
main.go                    # Entry point; passes version vars to cmd package
cmd/
  root.go                  # rootCmd, --workdir flag, getEffectiveWorkDir()
  root_ca.go               # root-ca generate + list
  intermediate_ca.go       # intermediate-ca generate + list
  server_cert.go           # server-cert generate + list
  client_cert.go           # client-cert generate + list
pkg/pki/pki.go             # All PKI helpers (no cobra dependencies)
```

Legacy `openssl/` and `step/` directories at the repo root are historical artefacts from before the CLI rewrite — do not touch them.

## Storage Layout

Default root: `~/.homepki` (overridable via `--workdir` flag or `HOMEPKI_WORKDIR` env var).

```
~/.homepki/
└── {rootCALiteralName}/           # domain with dots replaced by dashes, e.g. runlocal-dev
    ├── {rootCALiteralName}-defaults.conf
    ├── ca/
    │   ├── {name}.conf
    │   ├── {name}-root-ca.crt
    │   ├── private/{name}-root-ca.key
    │   └── db/
    └── {intermediateCAName}/
        ├── {name}.conf
        ├── {name}-intermediate-ca.crt
        ├── {name}-intermediate-ca-chain.crt
        ├── private/{name}-intermediate-ca.key
        ├── db/
        ├── server-tls/
        │   ├── {server}.conf
        │   ├── {server}.crt
        │   └── {server}.key
        └── client-tls/
            ├── {client}.conf
            ├── {client}.crt
            └── {client}.key
```

`GetRootCALiteralName(domain)` converts dots to dashes (e.g. `runlocal.dev` → `runlocal-dev`).

## Chain Verification

All `list` subcommands verify chain of trust using Go's `crypto/x509` (no openssl subprocess):

- `intermediate-ca list` → `pki.VerifyIntermediateCert(intermediateCert, rootCACert)`
- `server-cert list` / `client-cert list` → `pki.VerifyLeafCert(leafCert, intermediateCert, rootCACert)`

Output shows `[chain OK]` or `[INVALID chain: <reason>]` per entry.

## Release

Releases are triggered by pushing a `v*.*.*` tag. GoReleaser builds cross-platform binaries and updates the Homebrew tap (`HOMEBREW_TAP_GITHUB_TOKEN` secret required).

```bash
git tag v0.x.y && git push origin v0.x.y
```
