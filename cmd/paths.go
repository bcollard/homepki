package cmd

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bcollard/homepki/pkg/pki"
)

// forceGenerate backs the --force flag shared by every generate command.
var forceGenerate bool

// keyType backs the --key-type flag shared by every generate command.
var keyType string

// nameConstraints backs the --name-constraint flag of the CA generate commands.
var nameConstraints []string

// nameConstraintFlagUsage documents --name-constraint once for both CA tiers.
const nameConstraintFlagUsage = "Restrict the names this CA may issue for (repeatable), in openssl syntax: " +
	"permitted;DNS:.example.internal or excluded;IP:10.0.0.0/8. The permitted; prefix may be omitted"

// keyTypeFlagUsage documents --key-type once for every generate command.
var keyTypeFlagUsage = "Private key algorithm: " + strings.Join(pki.KeyTypes(), ", ")

// pathsPresent returns the subset of paths that exist on disk.
func pathsPresent(paths ...string) []string {
	var present []string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			present = append(present, p)
		}
	}
	return present
}

// replaceLeaf clears an existing leaf so that it can be issued again: the files
// on disk, and the row in the intermediate's CA database that would otherwise
// make openssl refuse a second certificate for the same subject.
func replaceLeaf(intermediateCADir, commonName string, files []string) error {
	removed, err := removeLeaf(intermediateCADir, commonName, files)
	if err != nil {
		return err
	}
	fmt.Printf("--force: replacing %s (removed %d file(s), %d CA database row(s))\n", commonName, len(files), removed)
	return nil
}

// removeLeaf deletes a leaf's files and its rows in the intermediate's CA
// database, and reports how many rows were removed.
func removeLeaf(intermediateCADir, commonName string, files []string) (int, error) {
	for _, f := range files {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return 0, err
		}
	}
	return pki.RemoveIndexEntry(filepath.Join(intermediateCADir, "db", "index.db"), commonName)
}

// rejectOutsideConstraints verifies a freshly signed leaf against its chain.
// openssl ca does not enforce name constraints when signing, so a leaf naming a
// host outside the root's or intermediate's constraints would be issued and
// then rejected by every TLS client. When that happens the leaf is removed —
// its files and its CA database row — and an error explains why.
func rejectOutsideConstraints(intermediateCADir, commonName, crtPath, intermediateCrtPath, rootCrtPath string, files []string) error {
	err := pki.VerifyLeafCert(crtPath, intermediateCrtPath, rootCrtPath, []x509.ExtKeyUsage{x509.ExtKeyUsageAny})
	if !pki.IsNameConstraintViolation(err) {
		return nil
	}
	if _, rmErr := removeLeaf(intermediateCADir, commonName, files); rmErr != nil {
		return fmt.Errorf("%w (and removing the rejected certificate failed: %v)", err, rmErr)
	}
	return fmt.Errorf("%w\n\nA CA in the chain carries name constraints that exclude one of this certificate's "+
		"Subject Alternative Names, so no TLS client would accept it. It has been removed; "+
		"check the constraints with: openssl x509 -noout -ext nameConstraints -in %s", err, intermediateCrtPath)
}

// warnLeafCNOutsideConstraints prints a warning when the common name homepki
// gives every generated leaf (<leaf>.<intermediate>.<domain>) falls outside the
// permitted DNS constraints, since server-cert and client-cert always add it as
// a Subject Alternative Name.
func warnLeafCNOutsideConstraints(domain, intermediate string) {
	probe, sample := "leaf.ca."+domain, "<leaf>.<intermediate>."+domain
	if intermediate != "" {
		probe, sample = "leaf."+intermediate+"."+domain, "<leaf>."+intermediate+"."+domain
	}
	if pki.PermittedDNSMismatch(nameConstraints, probe) {
		fmt.Printf("Warning: server-cert and client-cert always add %s as a Subject Alternative Name, "+
			"which these constraints do not permit. Only certificates signed with 'homepki sign' "+
			"can be issued under this CA.\n", sample)
	}
}

// nameConstraintsLine renders the openssl config line for a nameConstraints
// extension value, or nothing when there is none.
func nameConstraintsLine(ext string) string {
	if ext == "" {
		return ""
	}
	return "nameConstraints         = " + ext + "\n"
}

// rootCAPaths resolves the working directory and the root CA certificate for a domain.
func rootCAPaths(domain string) (workDir string, certPath string, err error) {
	baseDir, err := getEffectiveWorkDir()
	if err != nil {
		return "", "", err
	}
	literal := pki.GetRootCALiteralName(domain)
	workDir = filepath.Join(baseDir, literal)
	certPath = filepath.Join(workDir, "ca", fmt.Sprintf("%s-root-ca.crt", literal))
	return workDir, certPath, nil
}
