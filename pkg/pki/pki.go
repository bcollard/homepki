package pki

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// CreateDirectory creates a directory if it doesn't exist.
func CreateDirectory(path string) error {
	return os.MkdirAll(path, 0755)
}

// CreatePrivateDirectory creates a private directory with restricted permissions.
func CreatePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

// WriteFile writes content to a file.
func WriteFile(path string, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

// GetRootCALiteralName converts a domain name to a literal name (e.g., runlocal.dev -> runlocal-dev).
func GetRootCALiteralName(domain string) string {
	return strings.ReplaceAll(domain, ".", "-")
}

// DirectoryExists checks if a directory exists.
func DirectoryExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return info.IsDir(), nil
}

// FileExists checks if a file exists.
func FileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return !info.IsDir(), nil
}

// ListDirectories lists subdirectories in a given path.
func ListDirectories(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry.Name())
		}
	}
	return dirs, nil
}

// GetCertExpiry parses a PEM certificate file and returns its expiry time and days remaining.
func GetCertExpiry(certPath string) (time.Time, int, error) {
	cert, err := LoadCert(certPath)
	if err != nil {
		return time.Time{}, 0, err
	}
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	return cert.NotAfter, daysLeft, nil
}

// VerifyRootCert verifies that the root CA cert at rootCACertPath is a valid self-signed certificate.
func VerifyRootCert(rootCACertPath string) error {
	cert, err := LoadCert(rootCACertPath)
	if err != nil {
		return fmt.Errorf("root CA cert: %w", err)
	}
	// Verify alone accepts any certificate found in its own root pool, so the
	// self-signature has to be checked explicitly.
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("not self-signed: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// VerifyIntermediateCert verifies that the intermediate CA cert at intermediateCertPath
// was signed by the root CA at rootCACertPath.
func VerifyIntermediateCert(intermediateCertPath, rootCACertPath string) error {
	intermediateCert, err := LoadCert(intermediateCertPath)
	if err != nil {
		return fmt.Errorf("intermediate cert: %w", err)
	}
	rootCACert, err := LoadCert(rootCACertPath)
	if err != nil {
		return fmt.Errorf("root CA cert: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCACert)
	_, err = intermediateCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// VerifyLeafCert verifies that the leaf cert at leafCertPath was signed by the
// intermediate CA at intermediateCertPath, which in turn was signed by the root
// CA at rootCACertPath. keyUsages specifies the expected extended key usages
// (e.g. x509.ExtKeyUsageServerAuth or x509.ExtKeyUsageClientAuth).
func VerifyLeafCert(leafCertPath, intermediateCertPath, rootCACertPath string, keyUsages []x509.ExtKeyUsage) error {
	leafCert, err := LoadCert(leafCertPath)
	if err != nil {
		return fmt.Errorf("leaf cert: %w", err)
	}
	intermediateCert, err := LoadCert(intermediateCertPath)
	if err != nil {
		return fmt.Errorf("intermediate cert: %w", err)
	}
	rootCACert, err := LoadCert(rootCACertPath)
	if err != nil {
		return fmt.Errorf("root CA cert: %w", err)
	}
	return VerifyChain(leafCert, intermediateCert, rootCACert, keyUsages)
}

// VerifyChain verifies a leaf against its intermediate and root, including the
// name constraints any of them carry.
func VerifyChain(leaf, intermediate, root *x509.Certificate, keyUsages []x509.ExtKeyUsage) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     keyUsages,
	})
	return err
}

// SANs holds typed Subject Alternative Names.
type SANs struct {
	DNS    []string
	IPs    []net.IP
	Emails []string
	URIs   []*url.URL
}

// ParseSANs classifies --san values. Each may carry an explicit type prefix
// (`DNS:`, `IP:`, `email:`, `URI:`, any case); bare values are classified as IP
// when parseable, otherwise DNS. Duplicates are dropped.
func ParseSANs(values []string) (SANs, error) {
	var s SANs
	seen := map[string]bool{}
	for _, raw := range values {
		kind, value, err := classifySAN(raw)
		if err != nil {
			return SANs{}, err
		}
		if key := kind + ":" + value; seen[key] {
			continue
		} else {
			seen[key] = true
		}
		switch kind {
		case "DNS":
			s.DNS = append(s.DNS, value)
		case "IP":
			s.IPs = append(s.IPs, net.ParseIP(value))
		case "email":
			s.Emails = append(s.Emails, value)
		case "URI":
			u, err := url.Parse(value)
			if err != nil || u.Scheme == "" {
				return SANs{}, fmt.Errorf("invalid URI in SAN %q: want an absolute URI such as spiffe://example/svc", raw)
			}
			s.URIs = append(s.URIs, u)
		}
	}
	return s, nil
}

// SANsFromCSR returns the Subject Alternative Names a request carries.
func SANsFromCSR(csr *x509.CertificateRequest) SANs {
	return SANs{DNS: csr.DNSNames, IPs: csr.IPAddresses, Emails: csr.EmailAddresses, URIs: csr.URIs}
}

// Count returns the number of names.
func (s SANs) Count() int {
	return len(s.DNS) + len(s.IPs) + len(s.Emails) + len(s.URIs)
}

func classifySAN(s string) (string, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", fmt.Errorf("empty SAN entry")
	}
	for _, t := range []string{"DNS", "IP", "email", "URI"} {
		prefix := strings.ToLower(t) + ":"
		if strings.HasPrefix(strings.ToLower(s), prefix) {
			value := strings.TrimSpace(s[len(prefix):])
			if value == "" {
				return "", "", fmt.Errorf("empty value for SAN %q", s)
			}
			if t == "IP" && net.ParseIP(value) == nil {
				return "", "", fmt.Errorf("invalid IP address in SAN %q", s)
			}
			return t, value, nil
		}
	}
	if net.ParseIP(s) != nil {
		return "IP", s, nil
	}
	return "DNS", s, nil
}

// ListFiles lists files with a specific extension in a given path.
func ListFiles(path string, ext string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ext) {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}
