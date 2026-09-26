package cmd

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bcollard/homepki/pkg/pki"
)

func TestFullHierarchy(t *testing.T) {
	e := newPKIEnv(t)
	e.hierarchy("runlocal.dev")
	e.mustRun("server-cert", "-d", "runlocal.dev", "-i", "bu1", "-s", "gw",
		"--san", "gw.local", "--san", "10.0.0.5", "--san", "URI:spiffe://runlocal.dev/gw")
	e.mustRun("client-cert", "-d", "runlocal.dev", "-i", "bu1", "-c", "cli")

	root := e.cert("runlocal-dev", "ca", "runlocal-dev-root-ca.crt")
	if root.Subject.CommonName != "runlocal.dev" || !reflect.DeepEqual(root.Subject.Organization, []string{"runlocal-dev"}) {
		t.Errorf("root subject = %v", root.Subject)
	}
	if !root.IsCA || root.MaxPathLen != 1 {
		t.Errorf("root: IsCA=%v pathlen=%d", root.IsCA, root.MaxPathLen)
	}

	inter := e.cert("runlocal-dev", "bu1", "bu1-intermediate-ca.crt")
	if inter.Subject.CommonName != "bu1.runlocal.dev" || !reflect.DeepEqual(inter.Subject.OrganizationalUnit, []string{"bu1"}) {
		t.Errorf("intermediate subject = %v", inter.Subject)
	}
	if !inter.IsCA || inter.MaxPathLen != 0 || !inter.MaxPathLenZero {
		t.Errorf("intermediate: IsCA=%v pathlen=%d", inter.IsCA, inter.MaxPathLen)
	}

	// The chain file holds the intermediate, then the root.
	chain, err := os.ReadFile(e.path("runlocal-dev", "bu1", "bu1-intermediate-ca-chain.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(chain), "BEGIN CERTIFICATE") != 2 || e.cert("runlocal-dev", "bu1", "bu1-intermediate-ca-chain.crt").Subject.CommonName != "bu1.runlocal.dev" {
		t.Errorf("chain file is not intermediate + root:\n%s", chain)
	}

	server := e.cert("runlocal-dev", "bu1", "server-tls", "gw.crt")
	if server.Subject.CommonName != "gw.bu1.runlocal.dev" {
		t.Errorf("server CN = %q", server.Subject.CommonName)
	}
	if want := []string{"gw.bu1.runlocal.dev", "gw.local"}; !reflect.DeepEqual(server.DNSNames, want) {
		t.Errorf("server DNS SANs = %v, want %v (CN first)", server.DNSNames, want)
	}
	if len(server.IPAddresses) != 1 || server.IPAddresses[0].String() != "10.0.0.5" || len(server.URIs) != 1 {
		t.Errorf("server IP/URI SANs = %v %v", server.IPAddresses, server.URIs)
	}
	if !publicKeysEqual(server.PublicKey, e.key("runlocal-dev", "bu1", "server-tls", "gw.key").Public()) {
		t.Error("server key does not match its certificate")
	}

	client := e.cert("runlocal-dev", "bu1", "client-tls", "cli.crt")
	if !reflect.DeepEqual(client.DNSNames, []string{"cli.bu1.runlocal.dev"}) || client.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("client leaf: SANs=%v EKU=%v", client.DNSNames, client.ExtKeyUsage)
	}

	// Private material is private; nothing openssl-shaped is written.
	for _, p := range []string{
		e.path("runlocal-dev", "ca", "private", "runlocal-dev-root-ca.key"),
		e.path("runlocal-dev", "bu1", "private", "bu1-intermediate-ca.key"),
		e.path("runlocal-dev", "bu1", "server-tls", "gw.key"),
		e.path("runlocal-dev", "bu1", "client-tls", "cli.key"),
	} {
		if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0600 {
			t.Errorf("%s: mode %v (%v), want 0600", p, info.Mode().Perm(), err)
		}
	}
	for _, p := range []string{e.path("runlocal-dev", "ca", "private"), e.path("runlocal-dev", "bu1", "private")} {
		if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0700 {
			t.Errorf("%s: mode %v (%v), want 0700", p, info.Mode().Perm(), err)
		}
	}
	for _, p := range []string{
		e.path("runlocal-dev", "runlocal-dev-defaults.conf"),
		e.path("runlocal-dev", "ca", "db"),
		e.path("runlocal-dev", "bu1", "db"),
		e.path("runlocal-dev", "bu1", "bu1.conf"),
		e.path("runlocal-dev", "bu1", "server-tls", "gw.csr"),
		e.path("runlocal-dev", "bu1", "server-tls", "gw.conf"),
	} {
		if exists(p) {
			t.Errorf("%s should not exist", p)
		}
	}

	// Every tier lists as valid.
	for _, args := range [][]string{
		{"root-ca", "list"},
		{"intermediate-ca", "list", "-d", "runlocal.dev"},
		{"server-cert", "list", "-d", "runlocal.dev", "-i", "bu1"},
		{"client-cert", "list", "-d", "runlocal.dev", "-i", "bu1"},
	} {
		entries := e.list(args...)
		if len(entries) != 1 || !entries[0].ChainValid {
			t.Errorf("%v = %+v", args, entries)
		}
	}
}

func TestSignatureDigestFollowsIssuerKey(t *testing.T) {
	e := newPKIEnv(t)
	e.mustRun("root-ca", "-d", "digest.test", "--key-type", "ecdsa-p521")
	e.mustRun("intermediate-ca", "-d", "digest.test", "-n", "bu1", "--key-type", "ecdsa-p384")
	e.mustRun("server-cert", "-d", "digest.test", "-i", "bu1", "-s", "gw", "--key-type", "rsa")

	for path, want := range map[string]x509.SignatureAlgorithm{
		"ca/digest-test-root-ca.crt":  x509.ECDSAWithSHA512, // self-signed with P-521
		"bu1/bu1-intermediate-ca.crt": x509.ECDSAWithSHA512, // signed by the P-521 root
		"bu1/server-tls/gw.crt":       x509.ECDSAWithSHA384, // signed by the P-384 intermediate
	} {
		if got := e.cert("digest-test", path).SignatureAlgorithm; got != want {
			t.Errorf("%s signed with %v, want %v", path, got, want)
		}
	}
	if pub, ok := e.cert("digest-test", "bu1/server-tls/gw.crt").PublicKey.(interface{ Size() int }); !ok || pub.Size() != 256 {
		t.Error("server leaf key is not RSA-2048")
	}
}

func TestOverwriteProtection(t *testing.T) {
	e := newPKIEnv(t)
	e.hierarchy("over.test")
	e.mustRun("server-cert", "-d", "over.test", "-i", "bu1", "-s", "gw")

	rootPath := e.path("over-test", "ca", "over-test-root-ca.crt")
	before, _ := os.ReadFile(rootPath)
	if _, err := e.run("root-ca", "-d", "over.test"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("root-ca re-run: err = %v", err)
	}
	if after, _ := os.ReadFile(rootPath); string(after) != string(before) {
		t.Error("a refused root-ca re-run changed the certificate")
	}
	if _, err := e.run("intermediate-ca", "-d", "over.test", "-n", "bu1"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("intermediate-ca re-run: err = %v", err)
	}

	oldKey := e.key("over-test", "bu1", "server-tls", "gw.key")
	_, err := e.run("server-cert", "-d", "over.test", "-i", "bu1", "-s", "gw")
	if err == nil || !strings.Contains(err.Error(), "gw.crt") || !strings.Contains(err.Error(), "gw.key") {
		t.Errorf("server-cert re-run: err = %v", err)
	}
	if !publicKeysEqual(oldKey.Public(), e.key("over-test", "bu1", "server-tls", "gw.key").Public()) {
		t.Error("a refused server-cert re-run changed the key")
	}

	// --force re-issues the same subject: no CA database gets in the way.
	out := e.mustRun("server-cert", "-d", "over.test", "-i", "bu1", "-s", "gw", "--force")
	if !strings.Contains(out, "--force: replacing gw.bu1.over.test") {
		t.Errorf("--force output: %s", out)
	}
	if publicKeysEqual(oldKey.Public(), e.key("over-test", "bu1", "server-tls", "gw.key").Public()) {
		t.Error("--force kept the old key")
	}
	if entries := e.list("server-cert", "list", "-d", "over.test", "-i", "bu1"); len(entries) != 1 || !entries[0].ChainValid {
		t.Errorf("after --force: %+v", entries)
	}

	// Forcing the root orphans the tier below; the forced tier still lists OK.
	e.mustRun("root-ca", "-d", "over.test", "--force")
	if roots := e.list("root-ca", "list"); !roots[0].ChainValid {
		t.Errorf("forced root lists as invalid: %+v", roots)
	}
	inter := e.list("intermediate-ca", "list", "-d", "over.test")
	if inter[0].ChainValid || !strings.Contains(inter[0].ChainError, "unknown authority") {
		t.Errorf("intermediate under a replaced root: %+v", inter)
	}
	// Issuing under a CA whose root was replaced still works; the leaf just
	// does not verify, which checkLeaf reports.
	if _, err := e.run("server-cert", "-d", "over.test", "-i", "bu1", "-s", "gw2"); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("leaf under an orphaned intermediate: err = %v", err)
	}
	if exists(e.path("over-test", "bu1", "server-tls", "gw2.crt")) {
		t.Error("a leaf that does not verify was written")
	}
}

func TestLegacyLeftoversRemoved(t *testing.T) {
	e := newPKIEnv(t)
	e.hierarchy("legacy.test")
	e.mustRun("server-cert", "-d", "legacy.test", "-i", "bu1", "-s", "gw")

	// What a pre-0.7.0 workdir holds next to the certificates.
	legacy := []string{
		e.path("legacy-test", "legacy-test-defaults.conf"),
		e.path("legacy-test", "ca", "legacy-test.conf"),
		e.path("legacy-test", "ca", "legacy-test-root-ca.csr"),
		e.path("legacy-test", "ca", "db", "index.db"),
		e.path("legacy-test", "ca", "1000.pem"),
		e.path("legacy-test", "bu1", "bu1.conf"),
		e.path("legacy-test", "bu1", "bu1-intermediate-ca.csr"),
		e.path("legacy-test", "bu1", "bu1-signing-ext.conf"),
		e.path("legacy-test", "bu1", "db", "serial"),
		e.path("legacy-test", "bu1", "10A3.pem"),
		e.path("legacy-test", "bu1", "server-tls", "gw.conf"),
		e.path("legacy-test", "bu1", "server-tls", "gw.csr"),
	}
	kept := []string{
		e.path("legacy-test", "ca", "notes.pem"),
		e.path("legacy-test", "bu1", "README.txt"),
	}
	for _, p := range append(legacy, kept...) {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	e.mustRun("root-ca", "-d", "legacy.test", "--force")
	e.mustRun("intermediate-ca", "-d", "legacy.test", "-n", "bu1", "--force")
	e.mustRun("server-cert", "-d", "legacy.test", "-i", "bu1", "-s", "gw", "--force")

	for _, p := range legacy {
		if exists(p) {
			t.Errorf("legacy file survived --force: %s", p)
		}
	}
	for _, p := range kept {
		if !exists(p) {
			t.Errorf("unrelated file removed: %s", p)
		}
	}
	for _, d := range []string{e.path("legacy-test", "ca", "db"), e.path("legacy-test", "bu1", "db")} {
		if exists(d) {
			t.Errorf("legacy directory survived --force: %s", d)
		}
	}
}

func TestInputValidation(t *testing.T) {
	e := newPKIEnv(t)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"root-ca", "-d", "v.test", "--key-type", "ed448"}, "unknown key type"},
		{[]string{"root-ca", "-d", "v.test", "--name-constraint", "permitted;dirName:CN=x"}, "type must be one of DNS, IP, email, URI"},
		{[]string{"root-ca", "-d", "v.test", "--name-constraint", "IP:10.0.0.0"}, "needs a range"},
		{[]string{"intermediate-ca", "-d", "v.test", "-n", "bu1"}, "does not exist"},
		{[]string{"server-cert", "-d", "v.test", "-i", "bu1", "-s", "gw"}, "does not exist"},
		{[]string{"client-cert", "-d", "v.test", "-i", "bu1", "-c", "cli"}, "does not exist"},
	}
	for _, c := range cases {
		if _, err := e.run(c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: err = %v, want %q", c.args, err, c.want)
		}
	}
	// None of the refused commands wrote anything.
	if exists(e.path("v-test")) {
		t.Error("a refused command created the PKI directory")
	}

	e.hierarchy("v.test")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"server-cert", "-d", "v.test", "-i", "bu1", "-s", "gw", "--key-type", "rsa:4096"}, "unknown key type"},
		{[]string{"server-cert", "-d", "v.test", "-i", "bu1", "-s", "gw", "--san", "IP:not-an-ip"}, "invalid IP address"},
		{[]string{"server-cert", "-d", "v.test", "-i", "missing", "-s", "gw"}, "Intermediate CA certificate"},
		{[]string{"server-cert", "-d", "v.test", "-i", "bu1"}, `required flag(s) "server" not set`},
	} {
		if _, err := e.run(c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: err = %v, want %q", c.args, err, c.want)
		}
	}
	if exists(e.path("v-test", "bu1", "server-tls", "gw.crt")) {
		t.Error("a refused server-cert wrote a certificate")
	}
}

func TestMismatchedCAKeyDetected(t *testing.T) {
	e := newPKIEnv(t)
	e.hierarchy("mismatch.test")
	other, err := pki.GenerateKey("rsa")
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteKey(e.path("mismatch-test", "bu1", "private", "bu1-intermediate-ca.key"), other); err != nil {
		t.Fatal(err)
	}
	if _, err := e.run("server-cert", "-d", "mismatch.test", "-i", "bu1", "-s", "gw"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("err = %v, want a key mismatch", err)
	}
}

func TestNameConstraintsCommand(t *testing.T) {
	e := newPKIEnv(t)
	out := e.mustRun("root-ca", "-d", "klimax.internal",
		"--name-constraint", "permitted;DNS:.klimax.internal", "--name-constraint", "IP:10.0.0.0/8")
	if strings.Contains(out, "Warning") {
		t.Errorf("unexpected warning for a domain inside the constraint:\n%s", out)
	}
	root := e.cert("klimax-internal", "ca", "klimax-internal-root-ca.crt")
	if !root.PermittedDNSDomainsCritical || !reflect.DeepEqual(root.PermittedDNSDomains, []string{".klimax.internal"}) || len(root.PermittedIPRanges) != 1 {
		t.Errorf("root constraints = %v %v", root.PermittedDNSDomains, root.PermittedIPRanges)
	}

	e.mustRun("intermediate-ca", "-d", "klimax.internal", "-n", "bu1", "--name-constraint", "DNS:.bu1.klimax.internal")
	if got := e.cert("klimax-internal", "bu1", "bu1-intermediate-ca.crt").PermittedDNSDomains; !reflect.DeepEqual(got, []string{".bu1.klimax.internal"}) {
		t.Errorf("intermediate constraints = %v", got)
	}
	// An intermediate with no --name-constraint carries none of its own.
	e.mustRun("intermediate-ca", "-d", "klimax.internal", "-n", "bu2")
	if got := e.cert("klimax-internal", "bu2", "bu2-intermediate-ca.crt"); len(got.PermittedDNSDomains) != 0 || got.PermittedDNSDomainsCritical {
		t.Errorf("unconstrained intermediate carries constraints: %v", got.PermittedDNSDomains)
	}

	e.mustRun("server-cert", "-d", "klimax.internal", "-i", "bu1", "-s", "gw", "--san", "10.1.2.3")

	for _, san := range []string{"evil.example.com", "192.168.1.1"} {
		_, err := e.run("server-cert", "-d", "klimax.internal", "-i", "bu1", "-s", "bad", "--san", san)
		if err == nil || !strings.Contains(err.Error(), "not permitted") || !strings.Contains(err.Error(), "Nothing was written") {
			t.Errorf("--san %s: err = %v", san, err)
		}
		for _, f := range []string{"bad.crt", "bad.key"} {
			if exists(e.path("klimax-internal", "bu1", "server-tls", f)) {
				t.Errorf("--san %s: %s was written", san, f)
			}
		}
	}

	// A domain outside the constraint gets a warning, and its leaves are refused.
	out = e.mustRun("root-ca", "-d", "runlocal.dev", "--name-constraint", "DNS:.klimax.internal")
	if !strings.Contains(out, "Warning: server-cert and client-cert always add <leaf>.<intermediate>.runlocal.dev") {
		t.Errorf("missing warning:\n%s", out)
	}
	out = e.mustRun("intermediate-ca", "-d", "runlocal.dev", "-n", "bu1")
	if strings.Contains(out, "Warning") {
		t.Errorf("an unconstrained intermediate should not warn:\n%s", out)
	}
	if _, err := e.run("client-cert", "-d", "runlocal.dev", "-i", "bu1", "-c", "cli"); err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("client-cert under a constrained root: err = %v", err)
	}
}
