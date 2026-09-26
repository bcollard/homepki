---
name: homepki
description: "Issue local-development TLS certificates from a three-tier PKI (root CA → intermediate CA → server/client leaf) via the homepki CLI. Use whenever a recipe, demo, or test needs TLS or mTLS material on a workstation — instead of hand-rolled `openssl req`/`openssl ca` invocations, ad-hoc self-signed certs, mkcert, or `step certificate create`."
metadata:
  category: "security"
  requires:
    bins:
      - homepki
  cliHelp: "homepki --help"
---

# homepki — local development PKI

`homepki` is a single Go binary that builds and maintains a three-tier PKI on disk: a self-signed **root CA**, one or more **intermediate CAs** under it, and **server** or **client** leaf certificates under each intermediate. Keys, signing and chain verification all use Go's standard library (`crypto/x509`) — **it does not need `openssl` installed**.

**Prefer homepki over raw `openssl req`/`openssl ca`, one-off self-signed certs, `mkcert`, or `step certificate create`** whenever a local demo or test needs a real certificate hierarchy — in particular when it needs a proper chain (so a client can be handed a CA bundle), separate `serverAuth` and `clientAuth` leaves for mTLS, or several tenant-scoped intermediates.

It can also add the root CA to the system, Firefox/NSS and Java trust stores on macOS and Linux (`homepki trust install`), sign a CSR generated elsewhere (`homepki sign`), bundle a leaf as PKCS#12 (`--pkcs12`), and revoke leaves through CRLs (`homepki revoke`).

Project: https://github.com/bcollard/homepki

## Install (idempotent)

```bash
brew tap bcollard/homepki
brew install --cask homepki
```

No other dependency. The `openssl` commands in this document are optional, for inspecting results by hand.

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

Every generate command takes `--key-type`: `rsa` (2048-bit, the default), `ecdsa` / `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, or `ed25519`. Tiers are independent — an ECDSA leaf under an RSA intermediate is fine.

The **signature digest follows the issuing CA's key**, not the key being certified: SHA-256 for RSA and P-256, SHA-384 for P-384, SHA-512 for P-521, and Ed25519's own scheme for an Ed25519 CA. A root is signed by its own key.

**Do not use `ed25519` for anything a browser connects to.** Chrome, Safari and Firefox reject Ed25519 certificates. Go, OpenSSL 1.1.1+ and curl built on them accept Ed25519 for service-to-service TLS.

```bash
homepki intermediate-ca -d runlocal.dev -n bu1 --key-type ecdsa
homepki server-cert     -d runlocal.dev -i bu1 -s kong-gateway --key-type ecdsa-p384
```

## Validity

Every command that signs takes `--validity`: a number of days (`90d`) or a Go duration (`24h`, `30m`). Defaults: 2190 days for `root-ca` and `intermediate-ca`, 365 days for `server-cert`, `client-cert` and `sign`.

```bash
homepki root-ca     -d runlocal.dev --validity 3650d
homepki server-cert -d runlocal.dev -i bu1 -s kong-gateway --validity 24h   # short-lived, e.g. to test rotation
```

- **A certificate never outlives its issuer.** A longer request is capped at the issuer's `NotAfter`, and the command prints `Note: validity capped at the issuer's expiry, <date>.`
- There is no `y` suffix; write `3650d`.
- `NotBefore` is always 5 minutes in the past, so an already-expired certificate cannot be issued.

## Name constraints

`root-ca` and `intermediate-ca` take `--name-constraint` (repeatable) to limit the names the CA may issue for. Values use openssl syntax: `permitted;TYPE:value` or `excluded;TYPE:value`, with `TYPE` one of `DNS`, `IP`, `email`, `URI`. The `permitted;` prefix may be omitted. IP ranges accept CIDR (`10.0.0.0/8`) or address/netmask. The extension is marked critical.

```bash
homepki root-ca         -d klimax.internal --name-constraint "permitted;DNS:.klimax.internal"
homepki intermediate-ca -d klimax.internal -n bu1 --name-constraint "permitted;DNS:.bu1.klimax.internal"
```

- **Constrain the root when the root goes into the system trust store.** A trusted root restricted to `.klimax.internal` cannot be used to impersonate any other site, even if its key leaks. Go, macOS, Chrome and Firefox all enforce constraints on roots.
- **`.klimax.internal` matches subdomains only; `klimax.internal` matches the domain and its subdomains.**
- **Constraints apply per name type.** A `DNS` constraint alone leaves IP SANs unrestricted; add an `IP:` constraint to restrict those too.
- **Pick a domain inside the constraint.** Every `server-cert`/`client-cert` leaf carries `<leaf>.<intermediate>.<domain>` as a SAN, so the constraint must permit that. The CA commands print a warning when it does not.
- **Leaves outside the constraints are refused.** `server-cert`, `client-cert` and `sign` verify every new certificate against its chain before writing it. On a violation nothing is written and the command exits 1 with `x509: a root or intermediate certificate is not authorized to sign for this name: DNS name "..." is not permitted by any constraint`.
- **Constraints are fixed at issue time.** Adding or changing them means re-generating the CA with `--force`, which orphans everything beneath it.
- Inspect them with `openssl x509 -noout -ext nameConstraints -in <ca.crt>`.

## Listing and verifying

Every tier has a `list` subcommand (aliases `ls`, `l`) that reports expiry, days remaining, and a **verified chain of trust**:

```bash
homepki root-ca list                                          # no --domain: lists every root CA in the workdir
homepki intermediate-ca list -d runlocal.dev
homepki server-cert list     -d runlocal.dev -i bu1
homepki client-cert list     -d runlocal.dev -i bu1

homepki server-cert list -d runlocal.dev -i bu1 -o json       # machine-readable — prefer this when scripting
```

Chain verification uses `crypto/x509` and checks the extended key usage too, so a `clientAuth` leaf will not pass as a server certificate. Output shows `✓ OK` or `✗ INVALID: <reason>`.

`-o json` emits `{name, expires, days_left, chain_valid, chain_error}` per entry, and a bare `[]` when nothing exists. **Use `-o json` in scripts** — the table form is coloured with ANSI escapes and its column widths float with content.

Checking `chain_valid` after generating is the cheapest way to catch a CA that was replaced under a leaf (see [Re-issuing](#re-issuing)):

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

`client-cert` takes `--san` the same way. Use a `URI:` SAN for a SPIFFE ID:

```bash
homepki client-cert -d runlocal.dev -i bu1 -c my-client \
  --san URI:spiffe://runlocal.dev/ns/default/sa/my-client
```

## Trusting the Root CA

`homepki trust` adds the root CA to the trust stores of this machine, so browsers, curl and JVMs accept certificates issued under it without a flag. Three kinds of store are covered, picked with `--store` (repeatable or comma-separated):

| `--store` | Where | Tool used | Needs root |
| --- | --- | --- | --- |
| `system` | macOS: System keychain. Linux: the anchor directory of Debian/Ubuntu/Alpine, Fedora/RHEL, Arch or openSUSE, then the bundle is rebuilt | `security`; `update-ca-certificates` / `update-ca-trust` / `trust extract-compat` | yes (sudo) |
| `nss` | Every Firefox profile; on Linux also the Chrome/Chromium NSS database `~/.pki/nssdb` | `certutil` from NSS (`brew install nss`, `apt install libnss3-tools`, `dnf install nss-tools`) | no |
| `java` | `$JAVA_HOME/lib/security/cacerts` (or `jre/lib/security/cacerts` on JDK 8) | `$JAVA_HOME/bin/keytool` | only if the file is not writable |

**Without `--store`, every store available on the host is used**: `system`, plus `nss` when a profile and `certutil` are both found, plus `java` when `JAVA_HOME` is set. A skipped store gets a `Skipping ...` line. Naming a store explicitly makes a missing tool or profile an error.

```bash
homepki trust install   -d runlocal.dev                   # every available store
homepki trust install   -d runlocal.dev --store nss,java  # no sudo needed
homepki trust status                                      # every root CA in the workdir
homepki trust status    -d runlocal.dev -o json
homepki trust uninstall -d runlocal.dev
```

- **The system store prompts for a sudo password** unless homepki runs as root (e.g. in a container). Do not call it from an unattended script unless sudo is already cached or passwordless; `--store nss,java` avoids sudo entirely.
- `install` is idempotent: a store that already trusts the root is reported and skipped.
- `status` never prompts. In JSON, `.trusted` is true only when **every store checked** accepts the root, and `.stores[]` lists `{store, location, trusted, detail}` per store. Pass `--store` to status the same way you installed, or a missing optional store makes `.trusted` false.
- Restart Firefox and running JVMs after installing.
- **Windows is not covered**: homepki ships macOS and Linux binaries only.
- Trusting the root is not enough on its own: a server must still present `<intermediate>-intermediate-ca-chain.crt`, or clients cannot build the path from the leaf to the trusted root.

```bash
homepki trust status -d runlocal.dev --store nss -o json | jq -e '.[0].trusted' >/dev/null \
  || homepki trust install -d runlocal.dev --store nss
```

## Signing an external CSR

`homepki sign` issues a certificate for a request generated elsewhere — a service that made its own key, a cert-manager CSR, or a hand-rolled `openssl req`. The private key never reaches homepki.

```bash
openssl req -new -nodes -newkey rsa:2048 -keyout my-service.key -out my-service.csr \
  -subj "/O=runlocal-dev/OU=bu1/CN=my-service.bu1.runlocal.dev" \
  -addext "subjectAltName=DNS:my-service.bu1.runlocal.dev,DNS:my-service.local"

homepki sign -d runlocal.dev -i bu1 --csr my-service.csr
homepki sign -d runlocal.dev -i bu1 --csr my-client.csr --type client --name my-client
homepki sign -d runlocal.dev -i bu1 --csr my-service.csr --out ./my-service.crt
```

- **The subject must satisfy the intermediate's policy:** `O=` the root CA's literal name (dots → dashes) and `OU=` the intermediate name. Anything else is rejected, with the exact `-subj` to use printed in the error.
- **SANs come from the request** (DNS, IP, email and URI). A CSR with no SAN produces a certificate with no SAN and a warning — most TLS clients then reject it.
- Only the SANs and the subject (C, ST, L, O, OU, CN) are taken from the request. Every other extension it asks for is ignored: `basicConstraints`, `keyUsage` and `extendedKeyUsage` are set by homepki, so a request cannot ask to be a CA.
- `--type server` (default) or `client` picks the EKU and the destination directory. The certificate lands in `server-tls/<name>.crt` or `client-tls/<name>.crt` — where `<name>` is `--name`, or the first label of the CN — unless `--out` sends it elsewhere.
- Validity is the same fixed 365 days as a generated leaf.

## PKCS#12 bundles

`server-cert` and `client-cert` take `--pkcs12` to also write `<name>.p12` next to the `.crt`/`.key`: the private key, the leaf and the CA chain (intermediate then root). The password is `changeit` unless `--pkcs12-password` says otherwise — the same default as mkcert and the JDK.

```bash
homepki client-cert -d runlocal.dev -i bu1 -c my-client --pkcs12
keytool -list -keystore "$WORKDIR/runlocal-dev/bu1/client-tls/my-client.p12" -storepass changeit
```

The file uses the 3DES/SHA-1 PKCS#12 encoding, which Java, macOS Keychain, Windows and OpenSSL 3 all read without `-legacy`. It is mode `0600`. Re-issuing the leaf with `--force` but without `--pkcs12` deletes the old `.p12`, since it holds the replaced key.

## Revocation

`homepki revoke` adds a leaf's serial to its intermediate's CRL and re-signs the CRLs; `homepki crl` writes them without revoking anything.

```bash
homepki crl    -d runlocal.dev -i bu1                                    # empty CRLs, before a server needs them
homepki revoke -d runlocal.dev -i bu1 --client my-client
homepki revoke -d runlocal.dev -i bu1 --server kong-gateway --reason keyCompromise
homepki revoke -d runlocal.dev -i bu1 --cert ./my-service.crt           # e.g. from 'sign --out'
```

Files written (PEM):

| File | Content | Use |
| --- | --- | --- |
| `<int>/<int>-intermediate-ca.crl` | the intermediate's CRL | clients that check the leaf only |
| `ca/<root>-root-ca.crl` | the root's CRL (always empty) | |
| `<int>/<int>-crl-chain.crl` | both, intermediate first | nginx `ssl_crl`, Kong, `openssl verify -crl_check_all` — anything that checks every tier needs a CRL for each CA |

- The CRL file is the only record of revocations: `revoke` reads it and appends. Deleting it un-revokes everything.
- `--reason` takes an RFC 5280 name (`keyCompromise`, `superseded`, `cessationOfOperation`, ...); default `unspecified`.
- **CRLs expire.** `nextUpdate` is 365 days out by default (`--validity` changes it); OpenSSL-based servers reject a stale CRL with `CRL has expired`. Re-run `homepki crl` to refresh.
- `server-cert list` / `client-cert list` report a revoked leaf as `✗ INVALID: revoked on <date> (<reason>)`, `chain_valid: false` in JSON.
- Re-issuing a revoked name with `--force` gives it a new serial that is not revoked.
- Certificates carry no CRL distribution point; hand the CRL file to the server directly.
- Intermediates cannot be revoked; replace one with `intermediate-ca --force` (which also deletes its CRLs).

```bash
openssl verify -crl_check_all -CAfile "$CA_BUNDLE" \
  -CRLfile "$ROOT/bu1/bu1-crl-chain.crl" "$CLIENT_CRT"     # error 23: certificate revoked
```

## Storage layout

Everything lives under a single working directory, resolved in this order: `--workdir` flag → `$HOMEPKI_WORKDIR` → `~/.homepki`.

```
$WORKDIR/
└── runlocal-dev/                     # domain with dots → dashes
    ├── ca/                           # the root CA
    │   ├── runlocal-dev-root-ca.crt
    │   ├── runlocal-dev-root-ca.crl         # after revoke / crl
    │   └── private/runlocal-dev-root-ca.key
    └── bu1/                          # an intermediate CA
        ├── bu1-intermediate-ca.crt
        ├── bu1-intermediate-ca-chain.crt    # intermediate + root
        ├── bu1-intermediate-ca.crl          # after revoke / crl
        ├── bu1-crl-chain.crl                # intermediate CRL + root CRL
        ├── private/bu1-intermediate-ca.key
        ├── server-tls/{kong-gateway.crt,kong-gateway.key,kong-gateway.p12}
        └── client-tls/{my-client.crt,my-client.key}
```

Workdirs created before 0.7.0 also hold openssl `.conf` files, `.csr` files, `db/` directories and numbered `.pem` copies. They are unused and harmless; `--force` on a tier deletes that tier's leftovers.

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

**Private keys are written unencrypted** (PKCS#8 PEM), so no passphrase is ever prompted for and keys are directly loadable by servers and Kubernetes secrets. Key files are mode `0600` and CA `private/` directories are `0700`. This is a local-development tool: treat the workdir as sensitive and never commit it.

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

Prefer a fresh workdir per test run. Generation is fast, and it sidesteps `--force` entirely.

### Loading a leaf into Kubernetes

```bash
kubectl create secret tls kong-gateway-tls \
  --cert="$SERVER_CRT" --key="$SERVER_KEY"

kubectl create secret generic kong-ca \
  --from-file=ca.crt="$CA_BUNDLE"          # for mTLS / client verification
```

## Re-issuing

**Generate commands refuse to overwrite existing material.** A re-run without `--force` exits 1, prints what is in the way, and changes nothing on disk. `--force` replaces it:

| Command with `--force` | What it does |
| --- | --- |
| `root-ca -d X` | New root key + cert. **Every intermediate and leaf beneath it stops verifying.** |
| `intermediate-ca -d X -n Y` | New intermediate key + cert and chain file; deletes its CRLs. **Every leaf under it stops verifying.** |
| `server-cert` / `client-cert` | Overwrites the `.crt` and `.key` with a fresh key and certificate; rewrites or deletes the `.p12`. |
| `sign` | Overwrites the certificate at the output path. |

There is no CA database, so any number of certificates can exist for the same subject. Re-issuing under the same name is one command:

```bash
homepki server-cert -d runlocal.dev -i bu1 -s kong-gateway \
  --san kong.local --san 10.0.0.5 --force
```

`--force` on a **CA tier** is the dangerous one: it orphans everything below silently. `root-ca list` and `intermediate-ca list` still show `✓ OK` for the tier you just replaced, and only the tier *below* flips to `✗ INVALID: x509: certificate signed by unknown authority`. After forcing a CA, **check the lowest tier**, not the one you touched.

**In scripts, prefer a new name or a fresh workdir over `--force`.**

## Things to know when writing recipes

- **A re-run of a generate command fails instead of overwriting** (exit 1, nothing touched). That makes `set -e` scripts abort on a second run, so guard the call or pass `--force` deliberately:
  ```bash
  [ -f "$ROOT/ca/runlocal-dev-root-ca.crt" ] || homepki root-ca -d runlocal.dev
  ```
- **The `--workdir` flag is a persistent flag** and works on every subcommand, including the `list` subcommands. `$HOMEPKI_WORKDIR` is usually cleaner for a multi-command recipe.
- **Generate commands print a few lines on stdout** — what they are doing and each file written. Errors go to stderr. In scripts, rely on the exit code and confirm with `list -o json`.
- **Validity defaults:** CAs get 2190 days (~6 years), leaves get 365 days; `--validity` changes either. `list` reports `DAYS LEFT` so a recipe can check for imminent expiry, but renewal means re-issuing (see above).
- **Keys are RSA-2048 by default.** `--key-type ecdsa` (P-256), `ecdsa-p384`, `ecdsa-p521` or `ed25519` switches a tier. The digest follows the issuer's key: SHA-256 for RSA and P-256, SHA-384 for P-384, SHA-512 for P-521.
- **Serial numbers are random 128-bit values**, not a sequence.
- **Server leaves with an RSA key carry `keyEncipherment`** in addition to `digitalSignature`; ECDSA server leaves and all client leaves carry `digitalSignature` only.
- **`NotBefore` is backdated by 5 minutes**, so a new certificate is already valid inside a container or VM whose clock runs slightly behind.
- **The leaf CN is fully derived** from `<leaf>.<intermediate>.<domain>`. If a service must be reached at a name that does not fit that shape, add it with `--san` rather than trying to bend the leaf name — most TLS clients ignore the CN and match SANs only.
- **`intermediate-ca` is the only tier that builds a chain file.** There is no root-only bundle beyond `ca/<name>-root-ca.crt` itself, and no full-chain file that includes a leaf; concatenate if you need one.
- **Intermediates are `pathlen:0`**, so you cannot nest a second intermediate under one. The hierarchy is exactly three tiers deep.
- **Use several intermediates for tenant or environment separation** under one root (`-n bu1`, `-n bu2`) — that is the intended model, and it means a compromised or re-issued intermediate only orphans its own leaves.
- **Leaf directories are created lazily.** `server-cert list` before any server certificate exists prints `No server certificates found.` (or `[]`) and exits 0 rather than erroring — so a `list` returning empty is not a failure signal.
- `root-ca list` takes no `--domain`; it enumerates every root CA in the workdir. All other `list` commands require `--domain`, and the leaf ones also require `--intermediate`.
- **No command is interactive** except `trust install`/`uninstall` for the `system` store, or a `java` cacerts the user cannot write (sudo), so nothing else can hang an agent waiting on a passphrase or a DN prompt.

## Troubleshooting

### `✗ INVALID: x509: certificate signed by unknown authority`

The tier above was re-generated after this certificate was signed — see the hazard table. The certificate is unrecoverable (its issuer's key is gone); re-issue it, or rebuild the workdir.

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

- **Anything public-facing or production.** This is a local-development CA with unencrypted keys, file-based CRLs and no OCSP or ACME. Use Let's Encrypt/ACME or your organisation's PKI.
- **In-cluster certificate lifecycle** (rotation, renewal, issuing on demand) — use `cert-manager`. homepki is a good fit for generating the root and intermediate you then hand to cert-manager as a CA issuer, but not for managing leaves inside a cluster.
- **Windows.** homepki ships no Windows binary and `trust` has no Windows store; use `mkcert -install` there.
