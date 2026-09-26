package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// Validity periods, in days.
const (
	CAValidityDays   = 2190
	LeafValidityDays = 365
)

// backdate moves NotBefore into the past so a certificate is already valid on
// a machine whose clock runs a little behind — a container or a VM.
const backdate = 5 * time.Minute

// LeafKind selects the key usages of a leaf certificate.
type LeafKind int

const (
	ServerLeaf LeafKind = iota
	ClientLeaf
)

// ExtKeyUsage returns the extended key usage a leaf of this kind carries.
func (k LeafKind) ExtKeyUsage() x509.ExtKeyUsage {
	if k == ClientLeaf {
		return x509.ExtKeyUsageClientAuth
	}
	return x509.ExtKeyUsageServerAuth
}

// SelfSignRoot issues a self-signed root CA certificate. It may sign
// intermediate CAs only (pathlen 1).
func SelfSignRoot(key crypto.Signer, subject pkix.Name, nc NameConstraints) (*x509.Certificate, error) {
	tmpl, err := caTemplate(subject, 1, nc)
	if err != nil {
		return nil, err
	}
	return sign(tmpl, tmpl, key.Public(), key)
}

// SignIntermediate issues an intermediate CA certificate that may sign leaves
// only (pathlen 0).
func SignIntermediate(pub crypto.PublicKey, subject pkix.Name, nc NameConstraints, issuer *x509.Certificate, issuerKey crypto.Signer) (*x509.Certificate, error) {
	tmpl, err := caTemplate(subject, 0, nc)
	if err != nil {
		return nil, err
	}
	return sign(tmpl, issuer, pub, issuerKey)
}

// SignLeaf issues a server or client certificate. keyEncipherment is added for
// RSA server keys only: it describes RSA key transport and means nothing for
// an ECDSA key.
func SignLeaf(pub crypto.PublicKey, subject pkix.Name, sans SANs, kind LeafKind, issuer *x509.Certificate, issuerKey crypto.Signer) (*x509.Certificate, error) {
	tmpl, err := baseTemplate(subject, LeafValidityDays)
	if err != nil {
		return nil, err
	}
	tmpl.BasicConstraintsValid = true
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	if _, isRSA := pub.(*rsa.PublicKey); isRSA && kind == ServerLeaf {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{kind.ExtKeyUsage()}
	if tmpl.SubjectKeyId, err = subjectKeyID(pub); err != nil {
		return nil, err
	}
	tmpl.DNSNames, tmpl.IPAddresses, tmpl.EmailAddresses, tmpl.URIs = sans.DNS, sans.IPs, sans.Emails, sans.URIs
	return sign(tmpl, issuer, pub, issuerKey)
}

func caTemplate(subject pkix.Name, pathLen int, nc NameConstraints) (*x509.Certificate, error) {
	tmpl, err := baseTemplate(subject, CAValidityDays)
	if err != nil {
		return nil, err
	}
	tmpl.IsCA = true
	tmpl.BasicConstraintsValid = true
	tmpl.MaxPathLen = pathLen
	tmpl.MaxPathLenZero = pathLen == 0
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	nc.apply(tmpl)
	return tmpl, nil
}

func baseTemplate(subject pkix.Name, days int) (*x509.Certificate, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    now.Add(-backdate),
		NotAfter:     now.AddDate(0, 0, days),
	}, nil
}

// sign creates and parses a certificate. The signature algorithm follows
// crypto/x509's defaults for the issuer's key: SHA-256 for RSA and P-256,
// SHA-384 for P-384, SHA-512 for P-521. The authority key identifier is taken
// from the issuer, and CA certificates get a subject key identifier computed
// by crypto/x509.
func sign(tmpl, issuer *x509.Certificate, pub crypto.PublicKey, issuerKey crypto.Signer) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, issuerKey)
	if err != nil {
		return nil, fmt.Errorf("signing certificate for %s: %w", tmpl.Subject.CommonName, err)
	}
	return x509.ParseCertificate(der)
}

// newSerial returns a random positive 128-bit serial number. Random serials
// need no state on disk and never collide in practice.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, fmt.Errorf("generating serial number: %w", err)
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// subjectKeyID computes the RFC 5280 method-1 key identifier: the SHA-1 hash
// of the subjectPublicKey bit string.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("encoding public key: %w", err)
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("decoding public key: %w", err)
	}
	sum := sha1.Sum(spki.PublicKey.Bytes)
	return sum[:], nil
}

// LoadCert reads the first certificate in a PEM file, skipping any text before
// it (certificates written by older homepki releases start with a text dump).
func LoadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("no certificate PEM block found in %s", path)
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing %s: %w", path, err)
			}
			return cert, nil
		}
	}
}

// WriteCerts writes one or more certificates to a PEM file, in order.
func WriteCerts(path string, certs ...*x509.Certificate) error {
	var buf bytes.Buffer
	for _, c := range certs {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return err
		}
	}
	return os.WriteFile(path, buf.Bytes(), 0644)
}

// CheckKeyPair reports an error when key is not the private key of cert —
// signing with a mismatched pair would produce certificates nothing verifies.
func CheckKeyPair(cert *x509.Certificate, key crypto.Signer) error {
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return fmt.Errorf("the private key does not match the certificate for %s", cert.Subject.CommonName)
	}
	return nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}
