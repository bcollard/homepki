package pki

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
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
	root, err := SelfSignRoot(rootKey, pkix.Name{Organization: []string{"test-local"}, CommonName: "test.local"}, rootNC)
	if err != nil {
		t.Fatal(err)
	}
	intermediateKey, err := GenerateKey(keyType)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := SignIntermediate(intermediateKey.Public(),
		pkix.Name{Organization: []string{"test-local"}, OrganizationalUnit: []string{"bu1"}, CommonName: "bu1.test.local"},
		intermediateNC, root, rootKey)
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
		parsed, kind, c.intermediate, c.intermediateKey)
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
