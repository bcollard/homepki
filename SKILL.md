---
name: homepki
description: "Issue local-development TLS certificates from a three-tier PKI (root CA → intermediate CA → server/client leaf) via the homepki CLI. Use whenever a recipe, demo, or test needs TLS or mTLS material on a workstation — instead of hand-rolled `openssl req`/`openssl ca` invocations, ad-hoc self-signed certs, mkcert, or `step certificate create`."
metadata:
  category: "security"
  requires:
    bins:
      - homepki
      - openssl
  cliHelp: "homepki --help"
---

# homepki — local development PKI

`homepki` is a Go CLI that drives `openssl` to build and maintain a three-tier PKI on disk: a self-signed **root CA**, one or more **intermediate CAs** under it, and **server** or **client** leaf certificates under each intermediate. It writes the openssl config files, key material, and CA databases for you, and verifies chains of trust with Go's `crypto/x509`.

**Prefer homepki over raw `openssl req`/`openssl ca`, one-off self-signed certs, `mkcert`, or `step certificate create`** whenever a local demo or test needs a real certificate hierarchy — in particular when it needs a proper chain (so a client can be handed a CA bundle), separate `serverAuth` and `clientAuth` leaves for mTLS, or several tenant-scoped intermediates.

Project: https://github.com/bcollard/homepki

## Install (idempotent)

```bash
brew tap bcollard/homepki
brew install --cask homepki
```

**`homepki` shells out to `openssl` and requires real OpenSSL (3.x), not macOS's bundled LibreSSL.** See [Requires real OpenSSL](#requires-real-openssl-not-libressl) below — this is the single most common failure.

## The three tiers

Every command needs to know which root CA it is working under, identified by its **domain** (`--domain` / `-d`). Intermediates are named (`--name` / `-n`), and leaves are named per intermediate (`--server` / `-s`, `--client` / `-c`).

```bash
homepki root-ca         -d runlocal.dev                                # self-signed root CA
homepki intermediate-ca -d runlocal.dev -n bu1                         # intermediate signed by the root
homepki server-cert     -d runlocal.dev -i bu1 -s kong-gateway         # serverAuth leaf
homepki client-cert     -d runlocal.dev -i bu1 -c my-client            # clientAuth leaf
```

Each generate command is **synchronous and creates its own directory tree** — the files are on disk and usable the moment it returns. Each tier requires the tier above it to exist already, and errors out clearly if it does not (`root CA directory ... does not exist. Please create the Root CA first`).

Subject DNs are derived, not configurable: organization is the root's literal name, OU is the intermediate name, and the CN is `<leaf>.<intermediate>.<domain>` (e.g. `kong-gateway.bu1.runlocal.dev`), which is also the leaf's first SAN.

## Listing and verifying

Every tier has a `list` subcommand (aliases `ls`, `l`) that reports expiry, days remaining, and a **verified chain of trust**:

```bash
homepki root-ca list                                          # no --domain: lists every root CA in the workdir
homepki intermediate-ca list -d runlocal.dev
homepki server-cert list     -d runlocal.dev -i bu1
homepki client-cert list     -d runlocal.dev -i bu1

homepki server-cert list -d runlocal.dev -i bu1 -o json       # machine-readable — prefer this when scripting
```

Chain verification is done in-process with `crypto/x509` (no `openssl verify` subprocess) and checks the extended key usage too, so a `clientAuth` leaf will not pass as a server certificate. Output shows `✓ OK` or `✗ INVALID: <reason>`.

`-o json` emits `{name, expires, days_left, chain_valid, chain_error}` per entry, and a bare `[]` when nothing exists. **Use `-o json` in scripts** — the table form is coloured with ANSI escapes and its column widths float with content.

Checking `chain_valid` after generating is the cheapest way to catch the re-issue hazards described below:

```bash
homepki server-cert list -d runlocal.dev -i bu1 -o json \
  | jq -e 'all(.[]; .chain_valid)' >/dev/null || echo "broken chain!"
```

## Subject Alternative Names

Server leaves accept extra SANs via a repeatable `--san`. The CN (`<server>.<intermediate>.<domain>`) is always included as the first DNS SAN; `--san` values are appended.

```bash
homepki server-cert -d runlocal.dev -i bu1 -s kong-gateway \
  --san kong.local \
  --san 192.168.1.10 \
  --san 'DNS:*.kong.local' \
  --san IP:::1
```

Bare values are auto-classified: parseable as an IP → `IP`, otherwise `DNS`. Prefix with `DNS:`, `IP:`, `email:`, or `URI:` to force a type. An invalid IP after an `IP:` prefix is rejected rather than silently treated as a hostname.

**Always single-quote SANs containing `*`** — an unquoted `--san DNS:*.kong.local` is glob-expanded by the shell and zsh fails the whole command with `no matches found`.

`client-cert` has no `--san` flag; a client leaf gets exactly one SAN, its CN.

## Storage layout

Everything lives under a single working directory, resolved in this order: `--workdir` flag → `$HOMEPKI_WORKDIR` → `~/.homepki`.

```
$WORKDIR/
└── runlocal-dev/                     # domain with dots → dashes
    ├── runlocal-dev-defaults.conf
    ├── ca/                           # the root CA
    │   ├── runlocal-dev.conf
    │   ├── runlocal-dev-root-ca.crt
    │   ├── private/runlocal-dev-root-ca.key
    │   └── db/{index.db,serial}
    └── bu1/                          # an intermediate CA
        ├── bu1.conf
        ├── bu1-intermediate-ca.crt
        ├── bu1-intermediate-ca-chain.crt    # intermediate + root, PEM only
        ├── private/bu1-intermediate-ca.key
        ├── db/{index.db,serial}
        ├── server-tls/{kong-gateway.conf,kong-gateway.crt,kong-gateway.key}
        └── client-tls/{my-client.conf,my-client.crt,my-client.key}
```

The domain's dots become dashes (`runlocal.dev` → `runlocal-dev`) for the directory and the O= field, but the root CA's CN keeps the real domain.

Paths you will actually wire into a recipe:

```bash
WORKDIR="${HOMEPKI_WORKDIR:-$HOME/.homepki}"
ROOT=$WORKDIR/runlocal-dev
CA_BUNDLE=$ROOT/bu1/bu1-intermediate-ca-chain.crt       # hand this to clients as the trust store
SERVER_CRT=$ROOT/bu1/server-tls/kong-gateway.crt
SERVER_KEY=$ROOT/bu1/server-tls/kong-gateway.key
CLIENT_CRT=$ROOT/bu1/client-tls/my-client.crt
CLIENT_KEY=$ROOT/bu1/client-tls/my-client.key
```

Serve `$SERVER_CRT` with `$CA_BUNDLE` appended (or configure the intermediate separately) so clients that only trust the root can still build the path — a server that presents the leaf alone will fail verification against the root CA.

**Private keys are written unencrypted** (`openssl req -nodes`), so no passphrase is ever prompted for and keys are directly loadable by servers and Kubernetes secrets. Key files are mode `0600` and CA `private/` directories are `0700`. This is a local-development tool: treat the workdir as sensitive and never commit it.

## Standard recipe pattern

```bash
set -euo pipefail

export HOMEPKI_WORKDIR="$PWD/.pki"          # keep the demo's PKI local and disposable

homepki root-ca         -d runlocal.dev
homepki intermediate-ca -d runlocal.dev -n bu1
homepki server-cert     -d runlocal.dev -i bu1 -s kong-gateway --san kong.local
homepki client-cert     -d runlocal.dev -i bu1 -c my-client

# confirm the whole hierarchy verifies before using it
homepki intermediate-ca list -d runlocal.dev -o json | jq -e 'all(.[]; .chain_valid)' >/dev/null
homepki server-cert     list -d runlocal.dev -i bu1 -o json | jq -e 'all(.[]; .chain_valid)' >/dev/null
```

For a throwaway PKI, point `HOMEPKI_WORKDIR` at a temporary directory and delete it at the end — there is no `homepki delete`/`destroy` command, so teardown is `rm -rf` on the workdir:

```bash
export HOMEPKI_WORKDIR=$(mktemp -d)
trap 'rm -rf "$HOMEPKI_WORKDIR"' EXIT
```

Prefer a fresh workdir per test run. Generation is fast (RSA-2048), and it sidesteps every re-issue hazard below.

### Loading a leaf into Kubernetes

```bash
kubectl create secret tls kong-gateway-tls \
  --cert="$SERVER_CRT" --key="$SERVER_KEY"

kubectl create secret generic kong-ca \
  --from-file=ca.crt="$CA_BUNDLE"          # for mTLS / client verification
```

## Re-issuing: the three hazards

`homepki` has no revoke, renew, or delete command, and **generate commands are not idempotent**. Re-running one is destructive in a way that is easy to miss, because two of the three cases print success. Verified behaviour:

| Re-run | What happens |
| --- | --- |
| `root-ca -d X` on an existing domain | **Silently succeeds.** Generates a new root key + cert and resets `ca/db/{index.db,serial}`. Every intermediate and leaf beneath it is instantly orphaned. |
| `intermediate-ca -d X -n Y` on an existing intermediate | **Silently succeeds.** New intermediate key + cert, its `db/` reset. The intermediate re-verifies against the root, but every leaf under it is orphaned. |
| `server-cert`/`client-cert` with an existing name | **Fails** — `ERROR:There is already a certificate for /O=.../CN=...` — but the new `.key` and `.csr` have *already overwritten* the old ones. The surviving `.crt` no longer matches the `.key` on disk. |

The first two are silent: `root-ca list` and `intermediate-ca list` still show `✓ OK` for the tier you just replaced, and only the tier *below* flips to `✗ INVALID: x509: certificate signed by unknown authority`. So after any accidental re-run, **check the lowest tier**, not the one you touched.

The third case leaves a broken key/cert pair that no `list` output can detect — chain verification only inspects certificates, not whether the private key matches.

### Re-issuing a leaf, correctly

Because the intermediate's `index.db` enforces one certificate per subject DN, re-issuing under the same name requires clearing both the files and the database entry. This works and is the supported path:

```bash
ROOT="${HOMEPKI_WORKDIR:-$HOME/.homepki}/runlocal-dev"
CN="kong-gateway.bu1.runlocal.dev"

# 1. drop the database entry for that subject
grep -v "CN=$CN\$" "$ROOT/bu1/db/index.db" > "$ROOT/bu1/db/index.db.tmp" || true
mv "$ROOT/bu1/db/index.db.tmp" "$ROOT/bu1/db/index.db"

# 2. remove the stale leaf material
rm -f "$ROOT"/bu1/server-tls/kong-gateway.{crt,key,csr}

# 3. re-issue, optionally with different SANs
homepki server-cert -d runlocal.dev -i bu1 -s kong-gateway --san kong.local --san 10.0.0.5
```

Note the `|| true`: `grep -v` exits non-zero when it filters out the only line, which aborts a `set -e` script otherwise.

**The simpler alternative — and what to prefer in scripts — is to issue a new name** (`-s kong-gateway-v2`) or to start from a fresh workdir. Editing a CA database by hand is a last resort.

## Things to know when writing recipes

- **Every generate command is destructive on re-run.** Guard it, or build in a fresh workdir. To make a script safely resumable, test for the certificate first:
  ```bash
  [ -f "$ROOT/ca/runlocal-dev-root-ca.crt" ] || homepki root-ca -d runlocal.dev
  ```
- **The `--workdir` flag is a persistent flag** and works on every subcommand, including the `list` subcommands. `$HOMEPKI_WORKDIR` is usually cleaner for a multi-command recipe.
- **Generate commands are extremely verbose on stdout** — they echo each `openssl` invocation, the RSA progress dots, and the full text of the signed certificate. Redirect with `>/dev/null` in scripts and rely on the exit code, then confirm with `list -o json`.
- **Validity periods are fixed:** CAs get 2190 days (~6 years), leaves get 365 days. There is no flag to change them. `list` reports `DAYS LEFT` so a recipe can check for imminent expiry, but renewal means re-issuing (see above).
- **Keys are RSA-2048 with SHA-256**, set in the generated `*-defaults.conf`. No ECDSA option.
- **The leaf CN is fully derived** from `<leaf>.<intermediate>.<domain>`. If a service must be reached at a name that does not fit that shape, add it with `--san` rather than trying to bend the leaf name — most TLS clients ignore the CN and match SANs only.
- **`intermediate-ca` is the only tier that builds a chain file.** There is no root-only bundle beyond `ca/<name>-root-ca.crt` itself, and no full-chain file that includes a leaf; concatenate if you need one.
- **Intermediates are `pathlen:0`**, so you cannot nest a second intermediate under one. The hierarchy is exactly three tiers deep.
- **Use several intermediates for tenant or environment separation** under one root (`-n bu1`, `-n bu2`) — that is the intended model, and it means a compromised or re-issued intermediate only orphans its own leaves.
- **Leaf directories are created lazily.** `server-cert list` before any server certificate exists prints `No server certificates found.` (or `[]`) and exits 0 rather than erroring — so a `list` returning empty is not a failure signal.
- `root-ca list` takes no `--domain`; it enumerates every root CA in the workdir. All other `list` commands require `--domain`, and the leaf ones also require `--intermediate`.
- **No command is interactive.** `openssl` is always invoked with `-batch`/`prompt = no`, so nothing can hang an agent waiting on a passphrase or a DN prompt.

## Troubleshooting

### Requires real OpenSSL, not LibreSSL

macOS ships LibreSSL at `/usr/bin/openssl`, which does not support the `.include` directive homepki writes into every generated config. If LibreSSL comes first in `PATH`, **every** generate command fails with a cryptic error that never mentions LibreSSL:

```
error on line 2 of .../bu1/server-tls/kong-gateway.conf
...:error:0EFFF065:configuration file routines:CRYPTO_internal:missing equal sign:...
```

Check and fix:

```bash
openssl version                  # must say "OpenSSL 3.x", NOT "LibreSSL"
brew install openssl@3
export PATH="$(brew --prefix openssl@3)/bin:$PATH"
```

The Homebrew cask installs only the `homepki` binary, so this is worth asserting at the top of any recipe:

```bash
openssl version | grep -q '^OpenSSL' || { echo "need Homebrew OpenSSL, not LibreSSL"; exit 1; }
```

### `✗ INVALID: x509: certificate signed by unknown authority`

The tier above was re-generated after this certificate was signed — see the hazard table. The certificate is unrecoverable (its issuer's key is gone); re-issue it, or rebuild the workdir.

### `ERROR:There is already a certificate for /O=...`

A leaf with that name already exists. Note that the `.key` was overwritten before this error, so the existing `.crt`/`.key` pair is now mismatched — follow [Re-issuing a leaf, correctly](#re-issuing-a-leaf-correctly), or issue under a new name.

### Verifying by hand

```bash
openssl verify -CAfile "$ROOT/ca/runlocal-dev-root-ca.crt" \
  -untrusted "$ROOT/bu1/bu1-intermediate-ca.crt" "$SERVER_CRT"

openssl x509 -in "$SERVER_CRT" -noout -subject -ext subjectAltName,extendedKeyUsage

# does the key actually match the cert?
diff <(openssl x509 -in "$SERVER_CRT" -noout -pubkey) \
     <(openssl pkey -in "$SERVER_KEY" -pubout) && echo "key matches"
```

That last check is the one `homepki list` cannot do for you — run it after any leaf re-issue.

## When NOT to use homepki

- **Anything public-facing or production.** This is a local-development CA with unencrypted keys, fixed validity periods, and no revocation. Use Let's Encrypt/ACME or your organisation's PKI.
- **In-cluster certificate lifecycle** (rotation, renewal, issuing on demand) — use `cert-manager`. homepki is a good fit for generating the root and intermediate you then hand to cert-manager as a CA issuer, but not for managing leaves inside a cluster.
- **Browser-trusted local certificates with zero configuration** — `mkcert` installs its root into the OS and browser trust stores, which homepki does not do. If the goal is purely "no browser warning on localhost", mkcert is less work; homepki wins when you need the real hierarchy, mTLS client certificates, or multiple intermediates.
- **CI pipelines**, unless the job installs Homebrew OpenSSL. Generating a throwaway cert with a few lines of `openssl` is fewer moving parts there.
