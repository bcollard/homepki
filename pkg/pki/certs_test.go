package pki

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

type testChain struct {
	root, intermediate       *x509.Certificate
	rootKey, intermediateKey crypto.Signer
}

func newTestChain(t *testing.T, keyType string, rootNC, intermediateNC NameConstraints) testChain {
	t.Helper()
	rootKey, err := GenerateKey(keyType)
	if err != nil {
		t.Fatal(err)
	}
	root, err := SelfSignRoot(rootKey, pkix.Name{Organization: []string{"test-local"}, CommonName: "test.local"}, rootNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	intermediateKey, err := GenerateKey(keyType)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := SignIntermediate(intermediateKey.Public(),
		pkix.Name{Organization: []string{"test-local"}, OrganizationalUnit: []string{"bu1"}, CommonName: "bu1.test.local"},
		intermediateNC, 0, root, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return testChain{root, intermediate, rootKey, intermediateKey}
}

func (c testChain) leaf(t *testing.T, keyType string, kind LeafKind, sans ...string) *x509.Certificate {
	t.Helper()
	key, err := GenerateKey(keyType)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSANs(sans)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := SignLeaf(key.Public(),
		pkix.Name{Organization: []string{"test-local"}, OrganizationalUnit: []string{"bu1"}, CommonName: sans[0]},
		parsed, kind, 0, c.intermediate, c.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestIssuedChainShape(t *testing.T) {
	c := newTestChain(t, "rsa", NameConstraints{}, NameConstraints{})

	if !c.root.IsCA || c.root.MaxPathLen != 1 || c.root.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("root: IsCA=%v pathlen=%d ku=%v", c.root.IsCA, c.root.MaxPathLen, c.root.KeyUsage)
	}
	if !c.intermediate.IsCA || c.intermediate.MaxPathLen != 0 || !c.intermediate.MaxPathLenZero {
		t.Errorf("intermediate: IsCA=%v pathlen=%d zero=%v", c.intermediate.IsCA, c.intermediate.MaxPathLen, c.intermediate.MaxPathLenZero)
	}
	if len(c.root.SubjectKeyId) == 0 || string(c.intermediate.AuthorityKeyId) != string(c.root.SubjectKeyId) {
		t.Error("intermediate authority key identifier does not point at the root")
	}

	server := c.leaf(t, "rsa", ServerLeaf, "gw.bu1.test.local", "10.0.0.5")
	if server.IsCA || server.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
		t.Errorf("server leaf: IsCA=%v ku=%v", server.IsCA, server.KeyUsage)
	}
	if len(server.SubjectKeyId) != 20 || string(server.AuthorityKeyId) != string(c.intermediate.SubjectKeyId) {
		t.Error("server leaf key identifiers are wrong")
	}
	if len(server.IPAddresses) != 1 || server.DNSNames[0] != "gw.bu1.test.local" {
		t.Errorf("server leaf SANs: %v %v", server.DNSNames, server.IPAddresses)
	}
	if server.NotAfter.Sub(server.NotBefore).Hours() < 24*LeafValidityDays {
		t.Errorf("server leaf validity too short: %v", server.NotAfter.Sub(server.NotBefore))
	}
	if err := VerifyChain(server, c.intermediate, c.root, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}); err != nil {
		t.Errorf("server leaf does not verify: %v", err)
	}
	if err := VerifyChain(server, c.intermediate, c.root, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}); err == nil {
		t.Error("server leaf verified as a client certificate")
	}

	client := c.leaf(t, "ecdsa", ClientLeaf, "cli.bu1.test.local")
	if client.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("client leaf ku=%v", client.KeyUsage)
	}
	if err := VerifyChain(client, c.intermediate, c.root, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}); err != nil {
		t.Errorf("client leaf does not verify: %v", err)
	}
	if server.SerialNumber.Cmp(client.SerialNumber) == 0 {
		t.Error("two leaves share a serial number")
	}
}

func TestSignatureAlgorithmFollowsIssuerKey(t *testing.T) {
	cases := map[string]x509.SignatureAlgorithm{
		"rsa":        x509.SHA256WithRSA,
		"ecdsa-p256": x509.ECDSAWithSHA256,
		"ecdsa-p384": x509.ECDSAWithSHA384,
		"ecdsa-p521": x509.ECDSAWithSHA512,
	}
	for kt, want := range cases {
		c := newTestChain(t, kt, NameConstraints{}, NameConstraints{})
		// The leaf key type must not matter: the issuer's key picks the digest.
		leaf := c.leaf(t, "rsa", ServerLeaf, "gw.bu1.test.local")
		for name, cert := range map[string]*x509.Certificate{"root": c.root, "intermediate": c.intermediate, "leaf": leaf} {
			if cert.SignatureAlgorithm != want {
				t.Errorf("%s under %s CAs: signature %v, want %v", name, kt, cert.SignatureAlgorithm, want)
			}
		}
	}
}

func TestNameConstraintsEnforced(t *testing.T) {
	rootNC, err := ParseNameConstraints([]string{"permitted;DNS:.klimax.internal", "IP:10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	intermediateNC, err := ParseNameConstraints([]string{"permitted;DNS:.bu1.klimax.internal"})
	if err != nil {
		t.Fatal(err)
	}
	c := newTestChain(t, "ecdsa", rootNC, intermediateNC)
	if !c.root.PermittedDNSDomainsCritical || len(c.root.PermittedIPRanges) != 1 {
		t.Fatalf("root constraints missing: %v %v", c.root.PermittedDNSDomains, c.root.PermittedIPRanges)
	}
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	ok := c.leaf(t, "ecdsa", ServerLeaf, "gw.bu1.klimax.internal", "10.1.2.3")
	if err := VerifyChain(ok, c.intermediate, c.root, usages); err != nil {
		t.Errorf("permitted leaf rejected: %v", err)
	}
	for _, bad := range [][]string{
		{"gw.bu1.klimax.internal", "evil.example.com"},
		{"gw.bu2.klimax.internal"},
		{"gw.bu1.klimax.internal", "192.168.1.1"},
	} {
		leaf := c.leaf(t, "ecdsa", ServerLeaf, bad...)
		if err := VerifyChain(leaf, c.intermediate, c.root, usages); !IsNameConstraintViolation(err) {
			t.Errorf("leaf %q: want a name constraint violation, got %v", bad, err)
		}
	}
}

func TestWriteAndLoadCerts(t *testing.T) {
	c := newTestChain(t, "ecdsa", NameConstraints{}, NameConstraints{})
	path := filepath.Join(t.TempDir(), "chain.crt")
	if err := WriteCerts(path, c.intermediate, c.root); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCert(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(c.intermediate) {
		t.Error("LoadCert did not return the first certificate of the file")
	}
	if err := CheckKeyPair(c.root, c.rootKey); err != nil {
		t.Errorf("matching pair rejected: %v", err)
	}
	if err := CheckKeyPair(c.root, c.intermediateKey); err == nil {
		t.Error("mismatched pair accepted")
	}
}

func TestECDSAServerLeafHasNoKeyEncipherment(t *testing.T) {
	c := newTestChain(t, "ecdsa", NameConstraints{}, NameConstraints{})
	leaf := c.leaf(t, "ecdsa-p384", ServerLeaf, "gw.bu1.test.local")
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("ECDSA server leaf ku=%v, want digitalSignature only", leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ECDSA server leaf eku=%v", leaf.ExtKeyUsage)
	}
}

func TestLeafKindExtKeyUsage(t *testing.T) {
	if ServerLeaf.ExtKeyUsage() != x509.ExtKeyUsageServerAuth || ClientLeaf.ExtKeyUsage() != x509.ExtKeyUsageClientAuth {
		t.Error("LeafKind.ExtKeyUsage mapping is wrong")
	}
}

func TestSigningWithMismatchedIssuerKeyFails(t *testing.T) {
	c := newTestChain(t, "ecdsa", NameConstraints{}, NameConstraints{})
	key, err := GenerateKey("ecdsa")
	if err != nil {
		t.Fatal(err)
	}
	// The intermediate's certificate with the root's key: crypto/x509 refuses.
	if _, err := SignLeaf(key.Public(), pkix.Name{CommonName: "x"}, SANs{DNS: []string{"x"}}, ServerLeaf, 0, c.intermediate, c.rootKey); err == nil {
		t.Error("SignLeaf with a key that does not match the issuer: expected an error")
	}
	if _, err := SignIntermediate(key.Public(), pkix.Name{CommonName: "x"}, NameConstraints{}, 0, c.root, c.intermediateKey); err == nil {
		t.Error("SignIntermediate with a key that does not match the issuer: expected an error")
	}
}

func TestExcludedAndOtherConstraintTypes(t *testing.T) {
	nc, err := ParseNameConstraints([]string{
		"excluded;DNS:secret.test.local",
		"permitted;email:test.local",
		"permitted;URI:.test.local",
		"excluded;IP:10.0.0.0/8",
	})
	if err != nil {
		t.Fatal(err)
	}
	c := newTestChain(t, "ecdsa", nc, NameConstraints{})
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	cases := []struct {
		sans []string
		ok   bool
	}{
		{[]string{"gw.bu1.test.local"}, true},
		{[]string{"gw.bu1.test.local", "db.secret.test.local"}, false},
		{[]string{"gw.bu1.test.local", "email:ops@test.local"}, true},
		{[]string{"gw.bu1.test.local", "email:ops@example.com"}, false},
		{[]string{"gw.bu1.test.local", "URI:spiffe://gw.test.local/svc"}, true},
		{[]string{"gw.bu1.test.local", "URI:spiffe://example.com/svc"}, false},
		{[]string{"gw.bu1.test.local", "192.168.1.1"}, true},
		{[]string{"gw.bu1.test.local", "10.1.2.3"}, false},
	}
	for _, tc := range cases {
		err := VerifyChain(c.leaf(t, "ecdsa", ServerLeaf, tc.sans...), c.intermediate, c.root, usages)
		if tc.ok && err != nil {
			t.Errorf("%q: unexpected error %v", tc.sans, err)
		}
		if !tc.ok && !IsNameConstraintViolation(err) {
			t.Errorf("%q: want a name constraint violation, got %v", tc.sans, err)
		}
	}
}

func TestLoadCertLegacyAndErrors(t *testing.T) {
	c := newTestChain(t, "ecdsa", NameConstraints{}, NameConstraints{})
	dir := t.TempDir()

	// Releases before 0.7.0 let openssl ca write a text dump before the PEM block.
	legacy := filepath.Join(dir, "legacy.crt")
	text := "Certificate:\n    Data:\n        Version: 3 (0x2)\n"
	if err := os.WriteFile(legacy, append([]byte(text), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.root.Raw})...), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCert(legacy)
	if err != nil || !got.Equal(c.root) {
		t.Errorf("LoadCert(legacy) = %v, %v", got, err)
	}

	// A key block before the certificate is skipped.
	mixed := filepath.Join(dir, "mixed.pem")
	data := append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.intermediate.Raw})...)
	if err := os.WriteFile(mixed, data, 0644); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadCert(mixed); err != nil || !got.Equal(c.intermediate) {
		t.Errorf("LoadCert(mixed) = %v, %v", got, err)
	}

	bad := filepath.Join(dir, "bad.crt")
	if err := os.WriteFile(bad, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2}}), 0644); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.crt")
	if err := os.WriteFile(empty, []byte("no pem here"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{bad, empty, filepath.Join(dir, "missing.crt")} {
		if _, err := LoadCert(p); err == nil {
			t.Errorf("LoadCert(%s): expected an error", filepath.Base(p))
		}
	}
}

func TestSubjectKeyID(t *testing.T) {
	key, err := GenerateKey("rsa")
	if err != nil {
		t.Fatal(err)
	}
	a, err := subjectKeyID(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := subjectKeyID(key.Public())
	if len(a) != 20 || string(a) != string(b) {
		t.Errorf("subjectKeyID not a stable 20-byte SHA-1: %x %x", a, b)
	}
	if _, err := subjectKeyID("not a key"); err == nil {
		t.Error("subjectKeyID accepted an unsupported key type")
	}
}

func TestNewSerialIsPositiveAndBounded(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n, err := newSerial()
		if err != nil {
			t.Fatal(err)
		}
		if n.Sign() <= 0 || n.BitLen() > 128 {
			t.Fatalf("serial %v out of range", n)
		}
		if seen[n.String()] {
			t.Fatalf("serial %v repeated", n)
		}
		seen[n.String()] = true
	}
}
