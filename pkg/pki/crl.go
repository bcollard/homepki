package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"
)

// revocationReasons maps --reason values to their RFC 5280 section 5.3.1 codes.
// Reason 7 is unused in the RFC; removeFromCRL (8) and aACompromise (10) only
// make sense for delta CRLs and attribute certificates.
var revocationReasons = map[string]int{
	"unspecified":          0,
	"keyCompromise":        1,
	"cACompromise":         2,
	"affiliationChanged":   3,
	"superseded":           4,
	"cessationOfOperation": 5,
	"certificateHold":      6,
	"privilegeWithdrawn":   9,
}

// ParseRevocationReason converts a --reason value (case-insensitive) to its
// RFC 5280 code.
func ParseRevocationReason(s string) (int, error) {
	for name, code := range revocationReasons {
		if strings.EqualFold(name, strings.TrimSpace(s)) {
			return code, nil
		}
	}
	return 0, fmt.Errorf("unknown revocation reason %q (want one of: %s)", s, strings.Join(RevocationReasons(), ", "))
}

// RevocationReasons lists the accepted --reason values, sorted.
func RevocationReasons() []string {
	names := make([]string, 0, len(revocationReasons))
	for name := range revocationReasons {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// RevocationReasonName returns the RFC 5280 name of a reason code.
func RevocationReasonName(code int) string {
	for name, c := range revocationReasons {
		if c == code {
			return name
		}
	}
	return fmt.Sprintf("reason %d", code)
}

// LoadCRL reads a PEM certificate revocation list and checks that issuer
// signed it. A missing file returns nil and no error: a CA that has never
// revoked anything has no CRL yet.
func LoadCRL(path string, issuer *x509.Certificate) (*x509.RevocationList, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "X509 CRL" {
		return nil, fmt.Errorf("no X509 CRL PEM block found in %s", path)
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return nil, fmt.Errorf("%s was not signed by %s: %w", path, issuer.Subject.CommonName, err)
	}
	return crl, nil
}

// SignCRL issues a new CRL holding the entries of prev (which may be nil)
// plus add, with the next CRL number. Its nextUpdate is validity from now,
// capped at the issuer's expiry.
func SignCRL(prev *x509.RevocationList, add []x509.RevocationListEntry, validity time.Duration, issuer *x509.Certificate, issuerKey crypto.Signer) (*x509.RevocationList, error) {
	if validity == 0 {
		validity = Days(CRLValidityDays)
	}
	now := time.Now()
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-backdate),
		NextUpdate: now.Add(validity),
	}
	if tmpl.NextUpdate.After(issuer.NotAfter) {
		tmpl.NextUpdate = issuer.NotAfter
	}
	if prev != nil {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, prev.RevokedCertificateEntries...)
		if prev.Number != nil {
			tmpl.Number = new(big.Int).Add(prev.Number, big.NewInt(1))
		}
	}
	tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, add...)
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, issuerKey)
	if err != nil {
		return nil, fmt.Errorf("signing the CRL of %s: %w", issuer.Subject.CommonName, err)
	}
	return x509.ParseRevocationList(der)
}

// FindRevoked returns the entry revoking serial, or nil. A nil crl revokes
// nothing.
func FindRevoked(crl *x509.RevocationList, serial *big.Int) *x509.RevocationListEntry {
	if crl == nil {
		return nil
	}
	for i := range crl.RevokedCertificateEntries {
		if crl.RevokedCertificateEntries[i].SerialNumber.Cmp(serial) == 0 {
			return &crl.RevokedCertificateEntries[i]
		}
	}
	return nil
}

// WriteCRLs writes one or more CRLs to a PEM file, in order.
func WriteCRLs(path string, crls ...*x509.RevocationList) error {
	var buf bytes.Buffer
	for _, c := range crls {
		if err := pem.Encode(&buf, &pem.Block{Type: "X509 CRL", Bytes: c.Raw}); err != nil {
			return err
		}
	}
	return os.WriteFile(path, buf.Bytes(), 0644)
}
