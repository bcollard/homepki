package cmd

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func signSubject(cn string) pkix.Name {
	return pkix.Name{
		Organization:       []string{"sign-test"},
		OrganizationalUnit: []string{"bu1"},
		CommonName:         cn,
	}
}

func TestSignServerRequest(t *testing.T) {
	e := newPKIEnv(t)
	e.hierarchy("sign.test")
	csr := writeCSR(t, signSubject("svc.bu1.sign.test"), "svc.bu1.sign.test", "svc.local")

	out := e.mustRun("sign", "-d", "sign.test", "-i", "bu1", "--csr", csr)
	if !strings.Contains(out, "Serve it with the chain file") {
		t.Errorf("output: %s", out)
	}
	cert := e.cert("sign-test", "bu1", "server-tls", "svc.crt")
	if cert.IsCA {
		t.Error("a request asking for CA:TRUE was issued as a CA")
	}
	if !reflect.DeepEqual(cert.DNSNames, []string{"svc.bu1.sign.test", "svc.local"}) {
		t.Errorf("SANs = %v", cert.DNSNames)
	}
	if cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || cert.Subject.CommonName != "svc.bu1.sign.test" {
		t.Errorf("EKU=%v subject=%v", cert.ExtKeyUsage, cert.Subject)
	}
	if entries := e.list("server-cert", "list", "-d", "sign.test", "-i", "bu1"); len(entries) != 1 || !entries[0].ChainValid {
		t.Errorf("list = %+v", entries)
	}

	// Signing again refuses to overwrite, --force replaces it.
	if _, err := e.run("sign", "-d", "sign.test", "-i", "bu1", "--csr", csr); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("re-sign: err = %v", err)
	}
	serial := cert.SerialNumber
	e.mustRun("sign", "-d", "sign.test", "-i", "bu1", "--csr", csr, "--force")
	if e.cert("sign-test", "bu1", "server-tls", "svc.crt").SerialNumber.Cmp(serial) == 0 {
		t.Error("--force did not issue a new certificate")
	}
}

func TestSignClientRequestWithNameAndOut(t *testing.T) {
	e := newPKIEnv(t)
	e.hierarchy("sign.test")
	csr := writeCSR(t, signSubject("robot.bu1.sign.test"), "robot.bu1.sign.test")

	e.mustRun("sign", "-d", "sign.test", "-i", "bu1", "--csr", csr, "--type", "client", "--name", "bot")
	cert := e.cert("sign-test", "bu1", "client-tls", "bot.crt")
	if cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("client cert EKU=%v KU=%v", cert.ExtKeyUsage, cert.KeyUsage)
	}

	out := filepath.Join(t.TempDir(), "elsewhere.crt")
	e.mustRun("sign", "-d", "sign.test", "-i", "bu1", "--csr", csr, "--out", out)
	if !exists(out) {
		t.Fatalf("--out %s was not written", out)
	}
	// The same subject signed twice: no CA database refuses the second one.
	if exists(e.path("sign-test", "bu1", "server-tls", "robot.crt")) {
		t.Error("--out also wrote into server-tls/")
	}
}

func TestSignRejects(t *testing.T) {
	e := newPKIEnv(t)
	e.hierarchy("sign.test", "--name-constraint", "DNS:.sign.test")
	good := writeCSR(t, signSubject("svc.bu1.sign.test"), "svc.bu1.sign.test")

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"wrong O", []string{"--csr", writeCSR(t, pkix.Name{Organization: []string{"other"}, OrganizationalUnit: []string{"bu1"}, CommonName: "x.bu1.sign.test"}, "x.bu1.sign.test")}, "want O=sign-test"},
		{"wrong OU", []string{"--csr", writeCSR(t, pkix.Name{Organization: []string{"sign-test"}, OrganizationalUnit: []string{"bu2"}, CommonName: "x.bu1.sign.test"}, "x.bu1.sign.test")}, "want OU=bu1"},
		{"outside constraints", []string{"--csr", writeCSR(t, signSubject("evil.bu1.sign.test"), "evil.bu1.sign.test", "evil.example.com")}, "not permitted"},
		{"bad type", []string{"--csr", good, "--type", "peer"}, "--type must be server or client"},
		{"missing csr", []string{"--csr", filepath.Join(t.TempDir(), "none.csr")}, "no such file"},
		{"unusable CN", []string{"--csr", writeCSR(t, signSubject("*.bu1.sign.test"), "a.bu1.sign.test")}, "pass --name explicitly"},
	}
	for _, c := range cases {
		args := append([]string{"sign", "-d", "sign.test", "-i", "bu1"}, c.args...)
		if _, err := e.run(args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
	if files, _ := filepath.Glob(e.path("sign-test", "bu1", "*-tls", "*.crt")); len(files) != 0 {
		t.Errorf("refused requests wrote certificates: %v", files)
	}

	if _, err := e.run("sign", "-d", "sign.test", "-i", "nope", "--csr", good); err == nil || !strings.Contains(err.Error(), "Intermediate CA certificate") {
		t.Errorf("missing intermediate: err = %v", err)
	}
}

func TestSignWarnsWithoutSANs(t *testing.T) {
	e := newPKIEnv(t)
	e.hierarchy("sign.test")
	out := e.mustRun("sign", "-d", "sign.test", "-i", "bu1", "--csr", writeCSR(t, signSubject("bare.bu1.sign.test")))
	if !strings.Contains(out, "carries no Subject Alternative Names") {
		t.Errorf("missing warning:\n%s", out)
	}
	if cert := e.cert("sign-test", "bu1", "server-tls", "bare.crt"); len(cert.DNSNames) != 0 {
		t.Errorf("SANs invented: %v", cert.DNSNames)
	}
}
