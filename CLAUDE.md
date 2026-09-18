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
  skill.go                 # skill install + path; SetSkill() injection point
pkg/pki/pki.go             # All PKI helpers (no cobra dependencies)
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
