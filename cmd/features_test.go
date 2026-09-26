package cmd

import (
	"crypto"
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bcollard/homepki/pkg/pki"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestNoCapNoteForDefaults(t *testing.T) {
	e := newPKIEnv(t)
	e.mustRun("root-ca", "-d", "d.test")
	if out := e.mustRun("intermediate-ca", "-d", "d.test", "-n", "bu1"); strings.Contains(out, "capped") {
		t.Errorf("default intermediate under a fresh root printed a cap note:\n%s", out)
	}
}

func TestValidityFlag(t *testing.T) {
	e := newPKIEnv(t)
	e.mustRun("root-ca", "-d", "v.test", "--validity", "30d")
	out := e.mustRun("intermediate-ca", "-d", "v.test", "-n", "bu1", "--validity", "3650d")
	if !strings.Contains(out, "validity capped") {
		t.Errorf("intermediate outliving its root: no cap note\n%s", out)
	}
	root := e.cert("v-test", "ca", "v-test-root-ca.crt")
	inter := e.cert("v-test", "bu1", "bu1-intermediate-ca.crt")
	if d := time.Until(root.NotAfter); d > pki.Days(30) || d < pki.Days(29) {
		t.Errorf("30d root expires in %v", d)
	}
	if !inter.NotAfter.Equal(root.NotAfter) {
		t.Errorf("intermediate NotAfter %v not capped at root %v", inter.NotAfter, root.NotAfter)
	}

	e.mustRun("server-cert", "-d", "v.test", "-i", "bu1", "-s", "gw", "--validity", "2h")
	if d := time.Until(e.cert("v-test", "bu1", "server-tls", "gw.crt").NotAfter); d > 2*time.Hour || d < 119*time.Minute {
		t.Errorf("2h leaf expires in %v", d)
	}
	e.mustRun("client-cert", "-d", "v.test", "-i", "bu1", "-c", "cli", "--validity", "1d")
	if d := time.Until(e.cert("v-test", "bu1", "client-tls", "cli.crt").NotAfter); d > pki.Days(1) {
		t.Errorf("1d client leaf expires in %v", d)
	}

	if _, err := e.run("server-cert", "-d", "v.test", "-i", "bu1", "-s", "x", "--validity", "1y"); err == nil || !strings.Contains(err.Error(), "invalid validity") {
		t.Errorf("--validity 1y: %v", err)
	}
	if exists(e.path("v-test", "bu1", "server-tls", "x.crt")) {
		t.Error("an invalid --validity still wrote a certificate")
	}
}

func TestClientSANs(t *testing.T) {
	e := newPKIEnv(t)
	e.hierarchy("runlocal.dev")
	e.mustRun("client-cert", "-d", "runlocal.dev", "-i", "bu1", "-c", "cli",
		"--san", "URI:spiffe://runlocal.dev/ns/default/sa/cli", "--san", "email:cli@runlocal.dev")
	c := e.cert("runlocal-dev", "bu1", "client-tls", "cli.crt")
	if len(c.DNSNames) != 1 || c.DNSNames[0] != "cli.bu1.runlocal.dev" {
		t.Errorf("DNS SANs = %v", c.DNSNames)
	}
	if len(c.URIs) != 1 || c.URIs[0].String() != "spiffe://runlocal.dev/ns/default/sa/cli" {
		t.Errorf("URI SANs = %v", c.URIs)
	}
	if len(c.EmailAddresses) != 1 {
		t.Errorf("email SANs = %v", c.EmailAddresses)
	}
}

func TestEd25519Hierarchy(t *testing.T) {
	e := newPKIEnv(t)
	e.mustRun("root-ca", "-d", "ed.test", "--key-type", "ed25519")
	e.mustRun("intermediate-ca", "-d", "ed.test", "-n", "bu1", "--key-type", "ed25519")
	e.mustRun("server-cert", "-d", "ed.test", "-i", "bu1", "-s", "gw", "--key-type", "ed25519")
	if c := e.cert("ed-test", "bu1", "server-tls", "gw.crt"); c.SignatureAlgorithm != x509.PureEd25519 {
		t.Errorf("signature = %v", c.SignatureAlgorithm)
	}
	for _, l := range e.list("server-cert", "list", "-d", "ed.test", "-i", "bu1") {
		if !l.ChainValid {
			t.Errorf("%s: %s", l.Name, l.ChainError)
		}
	}
}

func TestPKCS12Flag(t *testing.T) {
	e := newPKIEnv(t)
	e.hierarchy("runlocal.dev")
	e.mustRun("server-cert", "-d", "runlocal.dev", "-i", "bu1", "-s", "gw", "--pkcs12")
	p12 := e.path("runlocal-dev", "bu1", "server-tls", "gw.p12")
	data, err := os.ReadFile(p12)
	if err != nil {
		t.Fatal(err)
	}
	key, cert, chain, err := pkcs12.DecodeChain(data, "changeit")
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Equal(e.cert("runlocal-dev", "bu1", "server-tls", "gw.crt")) || len(chain) != 2 {
		t.Error("p12 does not hold the certificate and its chain")
	}
	if !publicKeysEqual(key.(crypto.Signer).Public(), e.key("runlocal-dev", "bu1", "server-tls", "gw.key").Public()) {
		t.Error("p12 key differs from the .key file")
	}

	// The bundle counts as existing material.
	if _, err := e.run("server-cert", "-d", "runlocal.dev", "-i", "bu1", "-s", "gw"); err == nil {
		t.Error("re-issue without --force succeeded")
	}
	// Re-issuing without --pkcs12 drops the stale bundle, which holds the old key.
	e.mustRun("server-cert", "-d", "runlocal.dev", "-i", "bu1", "-s", "gw", "--force")
	if exists(p12) {
		t.Error("stale .p12 left after re-issue without --pkcs12")
	}

	e.mustRun("client-cert", "-d", "runlocal.dev", "-i", "bu1", "-c", "cli", "--pkcs12", "--pkcs12-password", "pw")
	data, _ = os.ReadFile(e.path("runlocal-dev", "bu1", "client-tls", "cli.p12"))
	if _, _, _, err := pkcs12.DecodeChain(data, "pw"); err != nil {
		t.Errorf("client p12 with custom password: %v", err)
	}
}

func TestRevokeAndCRL(t *testing.T) {
	e := newPKIEnv(t)
	e.hierarchy("runlocal.dev")
	e.mustRun("server-cert", "-d", "runlocal.dev", "-i", "bu1", "-s", "gw")
	e.mustRun("client-cert", "-d", "runlocal.dev", "-i", "bu1", "-c", "cli")
	e.mustRun("client-cert", "-d", "runlocal.dev", "-i", "bu1", "-c", "ok")

	e.mustRun("crl", "-d", "runlocal.dev", "-i", "bu1")
	inter := e.cert("runlocal-dev", "bu1", "bu1-intermediate-ca.crt")
	interCRL := e.path("runlocal-dev", "bu1", "bu1-intermediate-ca.crl")
	crl, err := pki.LoadCRL(interCRL, inter)
	if err != nil || crl == nil || len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("empty CRL: %v %v", crl, err)
	}
	for _, p := range [][]string{{"ca", "runlocal-dev-root-ca.crl"}, {"bu1", "bu1-crl-chain.crl"}} {
		if !exists(e.path(append([]string{"runlocal-dev"}, p...)...)) {
			t.Errorf("%v not written", p)
		}
	}

	e.mustRun("revoke", "-d", "runlocal.dev", "-i", "bu1", "-c", "cli", "--reason", "keyCompromise")
	if out := e.mustRun("revoke", "-d", "runlocal.dev", "-i", "bu1", "-c", "cli"); !strings.Contains(out, "already revoked") {
		t.Errorf("second revoke: %q", out)
	}
	crl, _ = pki.LoadCRL(interCRL, inter)
	cli := e.cert("runlocal-dev", "bu1", "client-tls", "cli.crt")
	if entry := pki.FindRevoked(crl, cli.SerialNumber); entry == nil || entry.ReasonCode != 1 {
		t.Errorf("cli not revoked for keyCompromise: %+v", entry)
	}
	if crl.Number.Int64() != 2 || len(crl.RevokedCertificateEntries) != 1 {
		t.Errorf("CRL number %v, %d entries", crl.Number, len(crl.RevokedCertificateEntries))
	}

	for _, l := range e.list("client-cert", "list", "-d", "runlocal.dev", "-i", "bu1") {
		switch l.Name {
		case "cli.crt":
			if l.ChainValid || !strings.Contains(l.ChainError, "revoked") || !strings.Contains(l.ChainError, "keyCompromise") {
				t.Errorf("cli listed as %v %q", l.ChainValid, l.ChainError)
			}
		case "ok.crt":
			if !l.ChainValid {
				t.Errorf("ok listed as invalid: %s", l.ChainError)
			}
		}
	}

	// The CRL survives a 'crl' refresh; re-issuing gives a new, unrevoked serial.
	e.mustRun("crl", "-d", "runlocal.dev", "-i", "bu1", "--validity", "7d")
	crl, _ = pki.LoadCRL(interCRL, inter)
	if pki.FindRevoked(crl, cli.SerialNumber) == nil || time.Until(crl.NextUpdate) > pki.Days(7) {
		t.Error("crl refresh lost the revocation or ignored --validity")
	}
	e.mustRun("client-cert", "-d", "runlocal.dev", "-i", "bu1", "-c", "cli", "--force")
	for _, l := range e.list("client-cert", "list", "-d", "runlocal.dev", "-i", "bu1") {
		if l.Name == "cli.crt" && !l.ChainValid {
			t.Errorf("re-issued cli still listed as %q", l.ChainError)
		}
	}

	// A certificate from another intermediate is refused.
	e.mustRun("intermediate-ca", "-d", "runlocal.dev", "-n", "bu2")
	e.mustRun("server-cert", "-d", "runlocal.dev", "-i", "bu2", "-s", "gw2")
	if _, err := e.run("revoke", "-d", "runlocal.dev", "-i", "bu1", "--cert", e.path("runlocal-dev", "bu2", "server-tls", "gw2.crt")); err == nil || !strings.Contains(err.Error(), "not issued by") {
		t.Errorf("revoking a foreign certificate: %v", err)
	}
	if _, err := e.run("revoke", "-d", "runlocal.dev", "-i", "bu1", "-s", "gw", "-c", "cli"); err == nil {
		t.Error("revoke with two targets accepted")
	}
	if _, err := e.run("revoke", "-d", "runlocal.dev", "-i", "bu1"); err == nil {
		t.Error("revoke without a target accepted")
	}

	// Replacing the intermediate drops CRLs its old key signed.
	e.mustRun("intermediate-ca", "-d", "runlocal.dev", "-n", "bu1", "--force")
	if exists(interCRL) || exists(e.path("runlocal-dev", "bu1", "bu1-crl-chain.crl")) {
		t.Error("intermediate --force left its old CRLs")
	}
}
