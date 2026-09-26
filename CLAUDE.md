# homepki

## Build & Run

```bash
go build ./...
go run . <command>
```

Version metadata is injected at build time via goreleaser (`-ldflags`). During development `version=dev`, `commit=none`, `date=unknown`.

## Project Layout

```
main.go                    # Entry point; passes version vars + embedded skill to cmd package
skill.go                   # //go:embed SKILL.md -> skillMD (package main)
SKILL.md                   # Agent Skill definition; single source of truth
cmd/
  root.go                  # rootCmd, --workdir flag, getEffectiveWorkDir()
  root_ca.go               # root-ca generate + list
  intermediate_ca.go       # intermediate-ca generate + list
  server_cert.go           # server-cert generate + list
  client_cert.go           # client-cert generate + list
  sign.go                  # sign (external CSRs)
  trust.go                 # trust install/uninstall/status: system (macOS, Linux), nss, java
  revoke.go                # revoke + crl (CRLs; no CA database, the CRL file is the record)
  leaf.go                  # generateLeaf: shared server-cert/client-cert issuance
  paths.go                 # shared flags, caFiles (CA cert/key locations), helpers
  skill.go                 # skill install + path; SetSkill() injection point
pkg/pki/pki.go             # file helpers, chain verification (VerifyRoot/VerifyIntermediate/VerifyChain, nil-safe), SAN parsing (no cobra dependencies)
pkg/pki/certs.go           # certificate issuance with crypto/x509
pkg/pki/keys.go            # --key-type -> key generation, PKCS#8 PEM read/write
pkg/pki/constraints.go     # --name-constraint parsing + Permit*/Exclude* builders for use in code
pkg/pki/csr.go             # CSR loading + subject policy validation
pkg/pki/crl.go             # CRL signing/loading, revocation reasons
pkg/pki/pkcs12.go          # PKCS#12 output (software.sslmate.com/src/go-pkcs12, LegacyDES)
pkg/pki/trust.go           # trust store detection + command construction (security, update-ca-*, certutil, keytool)
docs/                      # GitHub Pages site (see below)
```

## Website

`docs/` is served by GitHub Pages at https://bcollard.github.io/homepki/ (Pages source: `main` branch, `/docs` folder). It is a hand-written single-file page — `docs/index.html`, with `mark.svg`, `robots.txt`, `sitemap.xml` and `.nojekyll` alongside. No build step and no Jekyll; edit the HTML directly and push to `main` to deploy.

Preview it locally before pushing — `file://` URLs do not render reliably:

```bash
python3 -m http.server 8787 --bind 127.0.0.1 --directory docs
```

Two CSS constraints are load-bearing and easy to reintroduce: `.tiers` needs `grid-template-columns: minmax(0, 1fr)` (an implicit `auto` track sizes to the widest command and overflows phones), and the dark-mode `.btn-primary` needs dark ink (white on the mint accent fails WCAG AA at 2.3:1).

## Agent Skill

`SKILL.md` at the repo root is the canonical Agent Skill and is compiled into the binary. Because the repo root is `package main`, the embed lives in `skill.go` (package main) and is handed to the `cmd` package via `cmd.SetSkill()` — the same injection pattern as `cmd.SetVersion()`. `homepki skill install` writes it to `~/.claude/skills/homepki/SKILL.md`.

Edit `SKILL.md` only; never edit an installed copy. After changing CLI flags or behaviour, check whether `SKILL.md` needs the same update.

Legacy `openssl/` and `step/` directories at the repo root are historical artefacts from before the CLI rewrite — do not touch them.

## Storage Layout

Default root: `~/.homepki` (overridable via `--workdir` flag or `HOMEPKI_WORKDIR` env var).

```
~/.homepki/
└── {rootCALiteralName}/           # domain with dots replaced by dashes, e.g. runlocal-dev
    ├── ca/
    │   ├── {name}-root-ca.crt
    │   ├── {name}-root-ca.crl                              # after revoke / crl
    │   └── private/{name}-root-ca.key
    └── {intermediateCAName}/
        ├── {name}-intermediate-ca.crt
        ├── {name}-intermediate-ca-chain.crt
        ├── {name}-intermediate-ca.crl, {name}-crl-chain.crl   # after revoke / crl
        ├── private/{name}-intermediate-ca.key
        ├── server-tls/{server}.crt, {server}.key, [{server}.p12]
        └── client-tls/{client}.crt, {client}.key, [{client}.p12]
```

Trees created before 0.7.0 also contain openssl `.conf`/`.csr` files, `db/` and numbered `.pem` copies. They are ignored; `--force` on a tier removes that tier's leftovers (`removeOpenSSLLeftovers`).

`GetRootCALiteralName(domain)` converts dots to dashes (e.g. `runlocal.dev` → `runlocal-dev`).

## Overwrite Protection

Generate commands refuse to overwrite existing material and exit non-zero; `--force` replaces it. There is no CA database, so re-issuing a subject needs nothing beyond overwriting its files. `cmd/paths.go` holds the shared `--force`/`--key-type`/`--name-constraint`/`--validity` flag variables.

On Linux, `pki.SystemTrusts` reads the CA bundle files on every call; do not switch it to `x509.SystemCertPool`, which caches for the process lifetime and misses a root installed after the first status check.

`rootCmd.PersistentPreRun` sets `SilenceUsage`, so runtime errors print on their own while flag errors still show usage.

## Issuance and Chain Verification

No command shells out to `openssl`; the only external commands are the trust-store tools used by `trust` (`security`, `update-ca-certificates`/`update-ca-trust`/`trust`, `certutil`, `keytool`). `pkg/pki/certs.go` issues certificates with `x509.CreateCertificate`: random 128-bit serials, `NotBefore` backdated 5 minutes, `NotAfter` from `--validity` and capped at the issuer's, signature algorithm left to crypto/x509's default for the issuer key (SHA-256 for RSA/P-256, SHA-384 for P-384, SHA-512 for P-521).

Every issued leaf is checked with `pki.VerifyChain` before anything is written (`checkLeaf` in `cmd/paths.go`), which is what enforces name constraints at issue time. `list` subcommands verify the same way:

- `intermediate-ca list` → `pki.VerifyIntermediateCert(intermediateCert, rootCACert)`
- `server-cert list` / `client-cert list` → `pki.VerifyLeafCert(leafCert, intermediateCert, rootCACert)`, then the intermediate's CRL (`leafStatus` in `cmd/paths.go`)

## Release

Releases are triggered by pushing a `v*.*.*` tag. GoReleaser builds cross-platform binaries and updates the Homebrew tap (`HOMEBREW_TAP_GITHUB_TOKEN` secret required).

```bash
git tag v0.x.y && git push origin v0.x.y
```
