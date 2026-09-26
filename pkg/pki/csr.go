package pki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// leafNamePattern is what a leaf name may look like once derived from a CN:
// it becomes a file name inside the intermediate's server-tls/ or client-tls/.
var leafNamePattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$`)

// LoadCSR reads a PEM certificate signing request and verifies its signature.
func LoadCSR(path string) (*x509.CertificateRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s (expected a CERTIFICATE REQUEST)", path)
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%s holds a %q block, not a CERTIFICATE REQUEST", path, block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("signature on %s is invalid: %w", path, err)
	}
	return csr, nil
}

// ValidateCSRSubject checks a CSR against the signing policy of an intermediate
// CA: organizationName and organizationalUnitName must match exactly and a
// common name must be present. exampleCN is shown in the suggested openssl
// command when the subject does not fit.
func ValidateCSRSubject(csr *x509.CertificateRequest, org, ou, exampleCN string) error {
	var problems []string

	if !containsExactly(csr.Subject.Organization, org) {
		problems = append(problems, fmt.Sprintf("want O=%s, got O=%s", org, orNone(csr.Subject.Organization)))
	}
	if !containsExactly(csr.Subject.OrganizationalUnit, ou) {
		problems = append(problems, fmt.Sprintf("want OU=%s, got OU=%s", ou, orNone(csr.Subject.OrganizationalUnit)))
	}
	if strings.TrimSpace(csr.Subject.CommonName) == "" {
		problems = append(problems, "the request carries no common name (CN), which the CA policy requires")
	}
	if len(problems) == 0 {
		return nil
	}

	return fmt.Errorf("the request subject does not satisfy the CA policy:\n  %s\n\n"+
		"Regenerate the request with a matching subject, for example:\n"+
		"  openssl req -new -nodes -newkey rsa:2048 -keyout my.key -out my.csr \\\n"+
		"    -subj \"/O=%s/OU=%s/CN=%s\"",
		strings.Join(problems, "\n  "), org, ou, exampleCN)
}

// LeafNameFromCN derives the on-disk leaf name from a common name: the first
// DNS label, provided it is usable as a file name.
func LeafNameFromCN(cn string) (string, error) {
	label := strings.Split(strings.TrimSpace(cn), ".")[0]
	if !leafNamePattern.MatchString(label) {
		return "", fmt.Errorf("cannot derive a certificate name from CN %q — pass --name explicitly", cn)
	}
	return label, nil
}

func containsExactly(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func orNone(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, "+")
}
