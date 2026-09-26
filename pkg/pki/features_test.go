package pki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestParseValidity(t *testing.T) {
	def := 7 * time.Hour
	cases := map[string]time.Duration{
		"":     def,
		"90d":  90 * 24 * time.Hour,
		" 1d ": 24 * time.Hour,
		"24h":  24 * time.Hour,
		"90m":  90 * time.Minute,
	}
	for in, want := range cases {
		got, err := ParseValidity(in, def)
		if err != nil || got != want {
			t.Errorf("ParseValidity(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"0d", "-1d", "-5h", "1y", "d", "tenD", "0"} {
		if _, err := ParseValidity(bad, def); err == nil {
			t.Errorf("ParseValidity(%q): expected an error", bad)
		}
	}
}

func TestValidityIsCappedAtIssuer(t *testing.T) {
	c := newTestChain(t, "ecdsa", NameConstraints{}, NameConstraints{})
	key, _ := GenerateKey("ecdsa")
	leaf, err := SignLeaf(key.Public(), pkix.Name{CommonName: "gw"}, SANs{DNS: []string{"gw"}}, ServerLeaf,
		Days(100000), c.intermediate, c.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.NotAfter.Equal(c.intermediate.NotAfter) {
		t.Errorf("leaf NotAfter = %v, want the intermediate's %v", leaf.NotAfter, c.intermediate.NotAfter)
	}

	short, err := SignLeaf(key.Public(), pkix.Name{CommonName: "gw"}, SANs{DNS: []string{"gw"}}, ServerLeaf,
		time.Hour, c.intermediate, c.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(short.NotAfter); d > time.Hour || d < 59*time.Minute {
		t.Errorf("1h leaf expires in %v", d)
	}
}

func TestEd25519Chain(t *testing.T) {
	c := newTestChain(t, "ed25519", NameConstraints{}, NameConstraints{})
	if _, ok := c.rootKey.(ed25519.PrivateKey); !ok {
		t.Fatalf("root key is %T", c.rootKey)
	}
	leaf := c.leaf(t, "ed25519", ServerLeaf, "gw.bu1.test.local")
	if leaf.SignatureAlgorithm != x509.PureEd25519 || leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("ed25519 leaf: sig=%v ku=%v", leaf.SignatureAlgorithm, leaf.KeyUsage)
	}
	if err := VerifyChain(leaf, c.intermediate, c.root, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}); err != nil {
		t.Errorf("ed25519 chain does not verify: %v", err)
	}

	path := filepath.Join(t.TempDir(), "k.key")
	if err := WriteKey(path, c.rootKey); err != nil {
		t.Fatal(err)
	}
	back, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckKeyPair(c.root, back); err != nil {
		t.Errorf("reloaded ed25519 key: %v", err)
	}
}

func TestCRL(t *testing.T) {
	c := newTestChain(t, "ecdsa", NameConstraints{}, NameConstraints{})
	path := filepath.Join(t.TempDir(), "i.crl")

	if crl, err := LoadCRL(path, c.intermediate); crl != nil || err != nil {
		t.Fatalf("missing CRL: %v, %v; want nil, nil", crl, err)
	}

	empty, err := SignCRL(nil, nil, 0, c.intermediate, c.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Number.Int64() != 1 || len(empty.RevokedCertificateEntries) != 0 {
		t.Errorf("first CRL: number %v, %d entries", empty.Number, len(empty.RevokedCertificateEntries))
	}
	if d := time.Until(empty.NextUpdate); d < Days(CRLValidityDays-1) {
		t.Errorf("default nextUpdate in %v", d)
	}

	leaf := c.leaf(t, "ecdsa", ServerLeaf, "gw.bu1.test.local")
	entry := x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: time.Now(), ReasonCode: 1}
	crl, err := SignCRL(empty, []x509.RevocationListEntry{entry}, time.Hour, c.intermediate, c.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	if crl.Number.Int64() != 2 {
		t.Errorf("CRL number = %v, want 2", crl.Number)
	}
	if err := WriteCRLs(path, crl); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadCRL(path, c.intermediate)
	if err != nil {
		t.Fatal(err)
	}
	e := FindRevoked(loaded, leaf.SerialNumber)
	if e == nil || e.ReasonCode != 1 {
		t.Fatalf("revoked entry = %+v", e)
	}
	if FindRevoked(loaded, big.NewInt(42)) != nil || FindRevoked(nil, leaf.SerialNumber) != nil {
		t.Error("FindRevoked matched a serial that is not revoked")
	}

	// A CRL signed by another CA is refused.
	if _, err := LoadCRL(path, c.root); err == nil {
		t.Error("LoadCRL accepted a CRL signed by another CA")
	}
	// nextUpdate never goes past the issuer's expiry.
	long, err := SignCRL(nil, nil, Days(100000), c.intermediate, c.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !long.NextUpdate.Equal(c.intermediate.NotAfter) {
		t.Errorf("nextUpdate %v, want capped at %v", long.NextUpdate, c.intermediate.NotAfter)
	}
}

func TestRevocationReasons(t *testing.T) {
	for in, want := range map[string]int{"unspecified": 0, "keycompromise": 1, "Superseded": 4, "privilegeWithdrawn": 9} {
		if got, err := ParseRevocationReason(in); err != nil || got != want {
			t.Errorf("ParseRevocationReason(%q) = %d, %v", in, got, err)
		}
	}
	if _, err := ParseRevocationReason("lost"); err == nil {
		t.Error("unknown reason accepted")
	}
	if RevocationReasonName(1) != "keyCompromise" || RevocationReasonName(7) != "reason 7" {
		t.Errorf("RevocationReasonName: %q %q", RevocationReasonName(1), RevocationReasonName(7))
	}
}

func TestWritePKCS12(t *testing.T) {
	c := newTestChain(t, "rsa", NameConstraints{}, NameConstraints{})
	key, _ := GenerateKey("ecdsa")
	leaf, err := SignLeaf(key.Public(), pkix.Name{CommonName: "gw"}, SANs{DNS: []string{"gw"}}, ServerLeaf, 0, c.intermediate, c.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "gw.p12")
	if err := WritePKCS12(path, key, leaf, []*x509.Certificate{c.intermediate, c.root}, "s3cret"); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0600 {
		t.Errorf("p12 mode = %v", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	gotKey, gotCert, chain, err := pkcs12.DecodeChain(data, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if !gotCert.Equal(leaf) || len(chain) != 2 || !chain[0].Equal(c.intermediate) || !chain[1].Equal(c.root) {
		t.Error("p12 does not hold the leaf and its chain")
	}
	if !publicKeysEqual(gotKey.(crypto.Signer).Public(), key.Public()) {
		t.Error("p12 holds another key")
	}
	if _, _, _, err := pkcs12.DecodeChain(data, "wrong"); err == nil {
		t.Error("p12 opened with the wrong password")
	}
}

func TestLoadCerts(t *testing.T) {
	c := newTestChain(t, "ecdsa", NameConstraints{}, NameConstraints{})
	dir := t.TempDir()
	chain := filepath.Join(dir, "chain.crt")
	if err := WriteCerts(chain, c.intermediate, c.root); err != nil {
		t.Fatal(err)
	}
	// Text before, between and a foreign block must be skipped.
	data, _ := os.ReadFile(chain)
	data = append([]byte("Certificate:\n  text dump\n"), data...)
	data = append(data, []byte("-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n")...)
	os.WriteFile(chain, data, 0644)

	certs, err := LoadCerts(chain)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || !certs[0].Equal(c.intermediate) || !certs[1].Equal(c.root) {
		t.Errorf("LoadCerts returned %d certificates in the wrong order", len(certs))
	}
	if first, err := LoadCert(chain); err != nil || !first.Equal(c.intermediate) {
		t.Errorf("LoadCert on a chain: %v", err)
	}

	empty := filepath.Join(dir, "empty.pem")
	os.WriteFile(empty, []byte("nothing here"), 0644)
	if _, err := LoadCerts(empty); err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Errorf("LoadCerts on a file without certificates: %v", err)
	}
}

func TestVerifyIntermediateAndNil(t *testing.T) {
	c := newTestChain(t, "ecdsa", NameConstraints{}, NameConstraints{})
	if err := VerifyIntermediate(c.intermediate, c.root); err != nil {
		t.Errorf("VerifyIntermediate: %v", err)
	}
	if err := VerifyRoot(c.root); err != nil {
		t.Errorf("VerifyRoot: %v", err)
	}
	other := newTestChain(t, "ecdsa", NameConstraints{}, NameConstraints{})
	if err := VerifyIntermediate(c.intermediate, other.root); err == nil {
		t.Error("VerifyIntermediate accepted a foreign root")
	}
	leaf := c.leaf(t, "ecdsa", ServerLeaf, "gw.bu1.test.local")
	if err := VerifyIntermediate(leaf, c.root); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Errorf("VerifyIntermediate on a leaf: %v", err)
	}
	if err := VerifyRoot(c.intermediate); err == nil {
		t.Error("VerifyRoot accepted an intermediate")
	}

	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	for name, fn := range map[string]func() error{
		"VerifyChain nil leaf":         func() error { return VerifyChain(nil, c.intermediate, c.root, eku) },
		"VerifyChain nil intermediate": func() error { return VerifyChain(leaf, nil, c.root, eku) },
		"VerifyChain nil root":         func() error { return VerifyChain(leaf, c.intermediate, nil, eku) },
		"VerifyIntermediate nil":       func() error { return VerifyIntermediate(nil, c.root) },
		"VerifyIntermediate nil root":  func() error { return VerifyIntermediate(c.intermediate, nil) },
		"VerifyRoot nil":               func() error { return VerifyRoot(nil) },
	} {
		if err := fn(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestNameConstraintsBuilder(t *testing.T) {
	lan, err := ParseIPRange("10.0.0.7/255.0.0.0")
	if err != nil || lan.String() != "10.0.0.0/8" {
		t.Fatalf("ParseIPRange = %v, %v", lan, err)
	}
	if _, err := ParseIPRange("10.0.0.0"); err == nil {
		t.Error("ParseIPRange accepted an address without a range")
	}

	base := NameConstraints{}.PermitDNS(".klimax.internal")
	nc := base.ExcludeDNS("bad.klimax.internal").PermitIP(lan).ExcludeIP(&net.IPNet{IP: net.IPv4(10, 9, 0, 0).To4(), Mask: net.CIDRMask(16, 32)}).
		PermitEmail(".klimax.internal").ExcludeEmail("root@klimax.internal").PermitURI(".klimax.internal").ExcludeURI("x.klimax.internal")
	other := base.PermitDNS(".other.internal")

	if !reflect.DeepEqual(base.PermittedDNS, []string{".klimax.internal"}) {
		t.Errorf("chaining modified the base value: %v", base.PermittedDNS)
	}
	if !reflect.DeepEqual(nc.PermittedDNS, []string{".klimax.internal"}) || !reflect.DeepEqual(other.PermittedDNS, []string{".klimax.internal", ".other.internal"}) {
		t.Errorf("builders share state: %v / %v", nc.PermittedDNS, other.PermittedDNS)
	}

	parsed, err := ParseNameConstraints([]string{
		"permitted;DNS:.klimax.internal", "excluded;DNS:bad.klimax.internal",
		"IP:10.0.0.0/8", "excluded;IP:10.9.0.0/16",
		"email:.klimax.internal", "excluded;email:root@klimax.internal",
		"URI:.klimax.internal", "excluded;URI:x.klimax.internal",
	})
	if err != nil {
		t.Fatal(err)
	}
	if nc.Empty() || !reflect.DeepEqual(nc, parsed) {
		t.Errorf("builder result differs from the parser's:\n%+v\n%+v", nc, parsed)
	}

	// The built constraints are enforced like parsed ones.
	c := newTestChain(t, "ecdsa", NameConstraints{}.PermitDNS(".test.local"), NameConstraints{})
	key, _ := GenerateKey("ecdsa")
	leaf, err := SignLeaf(key.Public(), pkix.Name{CommonName: "evil.example"}, SANs{DNS: []string{"evil.example"}}, ServerLeaf, 0, c.intermediate, c.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChain(leaf, c.intermediate, c.root, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}); !IsNameConstraintViolation(err) {
		t.Errorf("leaf outside built constraints: %v", err)
	}
}
