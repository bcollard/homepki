package cmd

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bcollard/homepki/pkg/pki"
)

// leafRequest describes a leaf that server-cert or client-cert generates,
// key included.
type leafRequest struct {
	kind   pki.LeafKind
	label  string // "server" or "client"
	subdir string // "server-tls" or "client-tls"
	name   string
	sans   []string
	// inUse says what breaks when an existing pair is replaced.
	inUse string
}

// pkcs12Out and pkcs12Password back --pkcs12 and --pkcs12-password of
// server-cert and client-cert.
var (
	pkcs12Out      bool
	pkcs12Password string
)

// generateLeaf issues a key and certificate under an intermediate CA. The
// certificate is checked against its chain before anything is written, and
// its common name, <name>.<intermediate>.<domain>, is always its first SAN.
func generateLeaf(r leafRequest) error {
	if rootCADomain == "" {
		return fmt.Errorf("root CA domain name is required")
	}
	if intermediateCAName == "" {
		return fmt.Errorf("intermediate CA name is required")
	}
	if r.name == "" {
		return fmt.Errorf("%s name is required", r.label)
	}
	if err := pki.ValidateKeyType(keyType); err != nil {
		return err
	}
	validity, err := parseValidity(pki.LeafValidityDays)
	if err != nil {
		return err
	}

	rootCALiteralName := pki.GetRootCALiteralName(rootCADomain)
	baseDir, err := getEffectiveWorkDir()
	if err != nil {
		return err
	}
	workDir := filepath.Join(baseDir, rootCALiteralName)
	interFiles := intermediateCAFiles(workDir, intermediateCAName)
	intermediateCert, intermediateKey, err := interFiles.load("Intermediate CA")
	if err != nil {
		return err
	}
	rootCert, err := pki.LoadCert(rootCAFiles(workDir, rootCALiteralName).cert)
	if err != nil {
		return fmt.Errorf("root CA certificate: %w", err)
	}

	leafDir := filepath.Join(interFiles.dir, r.subdir)
	commonName := fmt.Sprintf("%s.%s.%s", r.name, intermediateCAName, rootCADomain)
	crtPath := filepath.Join(leafDir, r.name+".crt")
	keyPath := filepath.Join(leafDir, r.name+".key")
	p12Path := filepath.Join(leafDir, r.name+".p12")
	// Written by releases that drove openssl; removed along with the pair.
	stale := []string{filepath.Join(leafDir, r.name+".csr"), filepath.Join(leafDir, r.name+".conf")}
	if !pkcs12Out {
		// A bundle left from an earlier issue would hold the old key.
		stale = append(stale, p12Path)
	}

	if present := pathsPresent(crtPath, keyPath, p12Path); len(present) > 0 {
		if !forceGenerate {
			return fmt.Errorf("a %s certificate named %q already exists under %s/%s:\n  %s\n\n"+
				"Re-issuing overwrites its private key, so anything already %s that pair breaks. "+
				"Pass --force to replace it, or issue under another name",
				r.label, r.name, rootCADomain, intermediateCAName, strings.Join(present, "\n  "), r.inUse)
		}
		fmt.Printf("--force: replacing %s\n", commonName)
	}

	sans, err := pki.ParseSANs(append([]string{commonName}, r.sans...))
	if err != nil {
		return err
	}

	fmt.Printf("Generating %s certificate %s under %s/%s\n", r.label, r.name, rootCADomain, intermediateCAName)
	key, err := pki.GenerateKey(keyType)
	if err != nil {
		return err
	}
	cert, err := pki.SignLeaf(key.Public(), pkix.Name{
		Organization:       []string{rootCALiteralName},
		OrganizationalUnit: []string{intermediateCAName},
		CommonName:         commonName,
	}, sans, r.kind, validity, intermediateCert, intermediateKey)
	if err != nil {
		return err
	}
	if err := checkLeaf(cert, intermediateCert, rootCert, r.kind, interFiles.cert); err != nil {
		return err
	}

	if err := pki.CreateDirectory(leafDir); err != nil {
		return err
	}
	if err := pki.WriteKey(keyPath, key); err != nil {
		return err
	}
	if err := pki.WriteCerts(crtPath, cert); err != nil {
		return err
	}
	if pkcs12Out {
		if err := pki.WritePKCS12(p12Path, key, cert, []*x509.Certificate{intermediateCert, rootCert}, pkcs12Password); err != nil {
			return err
		}
	}
	if err := removePaths(stale...); err != nil {
		return err
	}

	fmt.Printf("Wrote %s\nWrote %s\n", keyPath, crtPath)
	if pkcs12Out {
		fmt.Printf("Wrote %s (key, certificate and CA chain; password %q)\n", p12Path, pkcs12Password)
	}
	noteCapped(cert, intermediateCert, validity)
	return nil
}
