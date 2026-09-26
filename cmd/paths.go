package cmd

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	"permitted;DNS:.example.internal or excluded;IP:10.0.0.0/8. Types: DNS, IP, email, URI. The permitted; prefix may be omitted"

// keyTypeFlagUsage documents --key-type once for every generate command.
var keyTypeFlagUsage = "Private key algorithm: " + strings.Join(pki.KeyTypes(), ", ")

// caFiles locates a CA tier's certificate and private key.
type caFiles struct {
	dir, cert, key string
}

func rootCAFiles(workDir, literal string) caFiles {
	dir := filepath.Join(workDir, "ca")
	return caFiles{
		dir:  dir,
		cert: filepath.Join(dir, literal+"-root-ca.crt"),
		key:  filepath.Join(dir, "private", literal+"-root-ca.key"),
	}
}

func intermediateCAFiles(workDir, name string) caFiles {
	dir := filepath.Join(workDir, name)
	return caFiles{
		dir:  dir,
		cert: filepath.Join(dir, name+"-intermediate-ca.crt"),
		key:  filepath.Join(dir, "private", name+"-intermediate-ca.key"),
	}
}

// load reads a CA's certificate and key and checks that they belong together.
func (f caFiles) load(tier string) (*x509.Certificate, crypto.Signer, error) {
	cert, err := pki.LoadCert(f.cert)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("%s certificate %s does not exist. Please create the %s first", tier, f.cert, tier)
		}
		return nil, nil, err
	}
	key, err := pki.LoadKey(f.key)
	if err != nil {
		return nil, nil, fmt.Errorf("%s private key: %w", tier, err)
	}
	if err := pki.CheckKeyPair(cert, key); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", tier, err)
	}
	return cert, key, nil
}

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

// removePaths deletes files and directories, ignoring those already gone.
func removePaths(paths ...string) error {
	for _, p := range paths {
		if err := os.RemoveAll(p); err != nil {
			return err
		}
	}
	return nil
}

// serialCopyPattern matches the per-serial certificate copies that openssl ca
// left in a CA directory (new_certs_dir) before homepki 0.7.0.
var serialCopyPattern = regexp.MustCompile(`^[0-9A-F]+\.pem$`)

// removeOpenSSLLeftovers deletes what homepki wrote when it drove openssl —
// config files, request files, the CA database and openssl's per-serial
// certificate copies — so a replaced CA leaves nothing misleading behind.
func removeOpenSSLLeftovers(dir string, files ...string) error {
	paths := append([]string{filepath.Join(dir, "db")}, files...)
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && serialCopyPattern.MatchString(e.Name()) {
				paths = append(paths, filepath.Join(dir, e.Name()))
			}
		}
	}
	return removePaths(paths...)
}

// parseNameConstraints parses --name-constraint and warns when the common name
// homepki gives every generated leaf (<leaf>.<intermediate>.<domain>) falls
// outside the permitted DNS subtrees, since server-cert and client-cert always
// add it as a Subject Alternative Name.
func parseNameConstraints(domain, intermediate string) (pki.NameConstraints, error) {
	nc, err := pki.ParseNameConstraints(nameConstraints)
	if err != nil {
		return nc, err
	}
	probe, sample := "leaf.ca."+domain, "<leaf>.<intermediate>."+domain
	if intermediate != "" {
		probe, sample = "leaf."+intermediate+"."+domain, "<leaf>."+intermediate+"."+domain
	}
	if nc.PermittedDNSMismatch(probe) {
		fmt.Printf("Warning: server-cert and client-cert always add %s as a Subject Alternative Name, "+
			"which these constraints do not permit. Only certificates signed with 'homepki sign' "+
			"can be issued under this CA.\n", sample)
	}
	return nc, nil
}

// checkLeaf verifies a freshly signed leaf against its chain before anything
// is written. A name outside a CA's constraints gets an explanation, since no
// TLS client would accept the certificate.
func checkLeaf(leaf, intermediate, root *x509.Certificate, kind pki.LeafKind, intermediatePath string) error {
	err := pki.VerifyChain(leaf, intermediate, root, []x509.ExtKeyUsage{kind.ExtKeyUsage()})
	if err == nil {
		return nil
	}
	if pki.IsNameConstraintViolation(err) {
		return fmt.Errorf("%w\n\nA CA in the chain carries name constraints that exclude one of this certificate's "+
			"Subject Alternative Names, so no TLS client would accept it. Nothing was written; "+
			"check the constraints with: openssl x509 -noout -ext nameConstraints -in %s", err, intermediatePath)
	}
	return fmt.Errorf("the new certificate does not verify against its chain: %w", err)
}

// rootCAPaths resolves the working directory and the root CA certificate for a domain.
func rootCAPaths(domain string) (workDir string, certPath string, err error) {
	baseDir, err := getEffectiveWorkDir()
	if err != nil {
		return "", "", err
	}
	literal := pki.GetRootCALiteralName(domain)
	workDir = filepath.Join(baseDir, literal)
	return workDir, rootCAFiles(workDir, literal).cert, nil
}
