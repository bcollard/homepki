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
docs/                      # GitHub Pages site: home page + docs/docs/ section (see below)
scripts/site.py            # website generator/validator (nav, sidebar, pager, search index, sitemap)
```

## Website

`docs/` is served by GitHub Pages at https://bcollard.github.io/homepki/ (Pages source: `main` branch, `/docs` folder, `.nojekyll`). Hand-written static HTML, no framework, no dependencies; push to `main` to deploy.

```
docs/
├── index.html          # minimal home page
├── 404.html            # served for any missing path: links are absolute (/homepki/...)
├── styles.css          # every style, light/dark/auto via :root[data-theme]
├── site.js             # theme toggle, release badge, sidebar, heading anchors, search, copy buttons
├── mark.svg · robots.txt · sitemap.xml (generated)
└── docs/               # documentation section, layout modelled on klimax.dev/docs
    ├── index.html      # overview, card grid
    ├── *.html          # one page per topic
    └── search-index.js # generated
```

**Run `python3 scripts/site.py` after every website change.** Shared parts are written between marker comments in each page — `<!-- nav -->`, `<!-- sidebar -->`, `<!-- breadcrumb -->`, `<!-- pager -->`, `<!-- footer -->` — so never edit inside them by hand. The script also regenerates `docs/docs/search-index.js` and `docs/sitemap.xml`, and exits non-zero on broken links or anchors, duplicate ids, `<h2>`/`<h3>` without an id, unbalanced tags, invalid JSON-LD, or a `<pre>` inside a `.callout`.

To add a docs page: copy an existing page for its `<head>` and markers, add it to `GROUPS` in `scripts/site.py` (sidebar order is also the prev/next order), give every `<h2>`/`<h3>` a slug `id`, run the script, commit the regenerated files with it.

- **Links must be relative** (`trust.html`, `../`). The site lives under `/homepki/`, so `/docs/...` would point at another site. Only `404.html` uses absolute `/homepki/` paths.
- **Release badge**: the nav shows the newest version in `docs/docs/changelog.html`, baked in by `site.py`; `site.js` refreshes it from the GitHub releases API (cached per session). Add the changelog entry and run `site.py` in the release commit, before tagging.
- **Callouts** are an icon plus one `<p>`: `.callout` is flex, a `<pre>` inside is squeezed into a column.
- Two CSS constraints are load-bearing: `.tiers` needs `grid-template-columns: minmax(0, 1fr)` (an implicit `auto` track sizes to the widest command and overflows phones), and `--on-brand` must stay dark ink in dark mode (white on the mint accent fails WCAG AA at 2.3:1).
- Content facts come from the code (`go run . <cmd> --help`, `pkg/pki`), not memory.

Preview locally — `file://` URLs do not render reliably:

```bash
python3 -m http.server 8787 --bind 127.0.0.1 --directory docs    # http://127.0.0.1:8787/
```

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

Before tagging, add the release to `docs/docs/changelog.html` and run `python3 scripts/site.py` (the nav badge takes its version from the changelog), in the same commit.

```bash
git tag -m v0.x.y v0.x.y && git push origin v0.x.y    # tags are signed: a bare `git tag v0.x.y` fails
```
