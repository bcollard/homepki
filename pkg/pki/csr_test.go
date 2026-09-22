package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCSR(t *testing.T, subject pkix.Name, dnsNames []string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  subject,
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "req.csr")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func matchingSubject() pkix.Name {
	return pkix.Name{
		Organization:       []string{"runlocal-dev"},
		OrganizationalUnit: []string{"bu1"},
		CommonName:         "gw.bu1.runlocal.dev",
	}
}

func TestLoadCSR(t *testing.T) {
	path := writeCSR(t, matchingSubject(), []string{"gw.bu1.runlocal.dev", "kong.local"})

	csr, err := LoadCSR(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if csr.Subject.CommonName != "gw.bu1.runlocal.dev" {
		t.Errorf("CN = %q", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("DNSNames = %v", csr.DNSNames)
	}
}

func TestLoadCSRRejectsNonPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.csr")
	if err := os.WriteFile(path, []byte("not a csr at all\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCSR(path); err == nil {
		t.Error("expected error for non-PEM input, got nil")
	}
}

func TestLoadCSRRejectsCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cert.pem")
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("whatever")})
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCSR(path); err == nil {
		t.Error("expected error for a CERTIFICATE block, got nil")
	}
}

func TestLoadCSRMissingFile(t *testing.T) {
	if _, err := LoadCSR(filepath.Join(t.TempDir(), "nope.csr")); err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestValidateCSRSubject(t *testing.T) {
	csr, err := LoadCSR(writeCSR(t, matchingSubject(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCSRSubject(csr, "runlocal-dev", "bu1", "gw.bu1.runlocal.dev"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateCSRSubjectMismatch(t *testing.T) {
	cases := []struct {
		name    string
		subject pkix.Name
		want    string
	}{
		{
			name:    "wrong O",
			subject: pkix.Name{Organization: []string{"acme"}, OrganizationalUnit: []string{"bu1"}, CommonName: "gw.bu1.runlocal.dev"},
			want:    "O=runlocal-dev",
		},
		{
			name:    "wrong OU",
			subject: pkix.Name{Organization: []string{"runlocal-dev"}, OrganizationalUnit: []string{"bu2"}, CommonName: "gw.bu1.runlocal.dev"},
			want:    "OU=bu1",
		},
		{
			name:    "missing O",
			subject: pkix.Name{OrganizationalUnit: []string{"bu1"}, CommonName: "gw.bu1.runlocal.dev"},
			want:    "O=runlocal-dev",
		},
		{
			name:    "missing CN",
			subject: pkix.Name{Organization: []string{"runlocal-dev"}, OrganizationalUnit: []string{"bu1"}},
			want:    "common name",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			csr, err := LoadCSR(writeCSR(t, c.subject, nil))
			if err != nil {
				t.Fatal(err)
			}
			err = ValidateCSRSubject(csr, "runlocal-dev", "bu1", "gw.bu1.runlocal.dev")
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestLeafNameFromCN(t *testing.T) {
	cases := map[string]string{
		"gw.bu1.runlocal.dev": "gw",
		"standalone":          "standalone",
		"my-service.bu1.test": "my-service",
	}
	for cn, want := range cases {
		got, err := LeafNameFromCN(cn)
		if err != nil {
			t.Errorf("LeafNameFromCN(%q): unexpected error: %v", cn, err)
			continue
		}
		if got != want {
			t.Errorf("LeafNameFromCN(%q) = %q, want %q", cn, got, want)
		}
	}
}

func TestLeafNameFromCNRejectsUnusable(t *testing.T) {
	for _, cn := range []string{"", "   ", "*.bu1.runlocal.dev", "../../etc/passwd", "a/b", ".", ".."} {
		if got, err := LeafNameFromCN(cn); err == nil {
			t.Errorf("LeafNameFromCN(%q) = %q, expected an error", cn, got)
		}
	}
}
